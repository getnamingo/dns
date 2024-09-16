<?php
// Ensure Swoole is loaded
if (!extension_loaded('swoole')) {
    exit("Please install the Swoole extension.\n");
}

// Initialize the PDO connection pool
$pool = new Swoole\Database\PDOPool(
    (new Swoole\Database\PDOConfig())
        ->withDriver('mysql')
        ->withHost('127.0.0.1')      // Update with your DB host
        ->withPort(3306)             // Update if your DB uses a different port
        ->withDbName('DB_NAME')    // Update with your DB name
        ->withUsername('DB_USER') // Update with your DB username
        ->withPassword('DB_PASS')      // Update with your DB password
        ->withCharset('utf8mb4')
);

// Create a UDP server
$server = new Swoole\Server("0.0.0.0", 53, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);

// Handle packets received
$server->on('Packet', function ($server, $data, $clientInfo) use ($pool) {

    // Get a PDO connection from the pool
    $pdo = $pool->get();

    try {
        // Define the DNS query header structure
        $queryHeader = unpack('nid/nflags/nqdcount/nancount/nnscount/narcount', $data);

        // Skip the DNS header to get to the domain name
        $offset = 12; // Size of the DNS header (12 bytes)
        $domainName = parseDomainName($data, $offset);

        // Extract the DNS record type from the query
        $queryType = unpack('nqtype', substr($data, $offset, 2))['qtype'];
        $offset += 2;
        $queryClass = unpack('nqclass', substr($data, $offset, 2))['qclass'];
        $offset += 2;

        // Map the record type to a human-readable form
        $recordTypes = [
            1 => 'A',
            2 => 'NS',
            5 => 'CNAME',
            6 => 'SOA',
            12 => 'PTR',
            15 => 'MX',
            16 => 'TXT',
            28 => 'AAAA',
            33 => 'SRV',
            35 => 'NAPTR',
            43 => 'DS',
            46 => 'RRSIG',
            47 => 'NSEC',
            48 => 'DNSKEY',
            50 => 'NSEC3',
            255 => 'ANY', // Added ANY type
            256 => 'URI',
        ];

        $recordTypeString = isset($recordTypes[$queryType]) ? $recordTypes[$queryType] : 'Unknown';

        echo "New $queryType ($recordTypeString) request for $domainName\n";

        $transactionId = substr($data, 0, 2);
        $flags = 0x8180; // Standard query response, no error
        $qdCount = $queryHeader['qdcount'];
        $anCount = 0; // Initialize answer count
        $nsCount = 0; // Initialize authority record count
        $arCount = 0; // Initialize additional record count

        // Extract the question section to echo back
        $questionSectionLength = $offset - 12;
        $questionSection = substr($data, 12, $questionSectionLength);

        // Check if domain exists
        $sql = "SELECT 1 FROM dns_records WHERE name = :name LIMIT 1";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([':name' => $domainName]);
        $domainExists = $stmt->fetchColumn();

        if (!$domainExists) {
            // Domain not found, set NXDOMAIN flag
            $flags = 0x8183; // 0x8180 with RCODE set to 3 for NXDOMAIN
            $anCount = 0; // No answers
            $response = $transactionId . pack('n', $flags) . pack('nnnn', $qdCount, $anCount, $nsCount, $arCount) . $questionSection;
            $server->sendto($clientInfo['address'], $clientInfo['port'], $response);
            $pool->put($pdo);
            return;
        }

        // Handle ANY queries
        if ($recordTypeString === 'ANY') {
            // Fetch all record types for the domain
            $sql = "SELECT * FROM dns_records WHERE name = :name";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':name' => $domainName,
            ]);
        } else {
            // Query the database for specific DNS records
            $sql = "SELECT * FROM dns_records WHERE name = :name AND type = :type";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':name' => $domainName,
                ':type' => $recordTypeString,
            ]);
        }

        $records = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Answer section
        $answerSection = '';
        $answerCount = 0;
        foreach ($records as $record) {
            // Name field: use a pointer to the domain name in the question section
            $namePointer = pack('n', 0xc00c); // Pointer to offset 12

            // Type field
            $typeCode = array_search($record['type'], $recordTypes);
            if ($typeCode === false) {
                break; // Skip unknown record types
            }
            $type = pack('n', $typeCode);

            // Class field
            $class = pack('n', 1); // IN

            // TTL field
            $ttl = pack('N', $record['ttl']);

            // RDATA
            $rdata = '';
            $rdlength = '';

            switch ($record['type']) {
                case 'A':
                    $rdata = inet_pton($record['content']);
                    if ($rdata === false) {
                        break; // Skip invalid IP addresses
                    }
                    $rdlength = pack('n', strlen($rdata));
                    break;
                case 'AAAA':
                    $rdata = inet_pton($record['content']);
                    if ($rdata === false) {
                        break; // Skip invalid IP addresses
                    }
                    $rdlength = pack('n', strlen($rdata));
                    break;
                case 'CNAME':
                case 'NS':
                case 'PTR':
                    $rdata = domainNameToDNSFormat($record['content']);
                    $rdlength = pack('n', strlen($rdata));
                    break;
                case 'MX':
                    if (isset($record['prio'])) {
                        $preference = (int)$record['prio'];
                    } elseif (isset($record['priority'])) {
                        $preference = (int)$record['priority'];
                    } else {
                        // Default preference value
                        $preference = 10;
                    }
                    $exchange = $record['content'];
                    $rdata = pack('n', $preference) . domainNameToDNSFormat($exchange);
                    $rdlength = pack('n', strlen($rdata));
                    break;
                case 'TXT':
                    $text = $record['content'];
                    $textLength = strlen($text);
                    $rdata = chr($textLength) . $text;
                    $rdlength = pack('n', $textLength + 1); // +1 for the length byte
                    break;
                case 'SOA':
                    list($mname, $rname, $serial, $refresh, $retry, $expire, $minimum) = explode(' ', $record['content']);
                    $rdata = domainNameToDNSFormat($mname) . domainNameToDNSFormat($rname) . pack('N', $serial) . pack('N', $refresh) . pack('N', $retry) . pack('N', $expire) . pack('N', $minimum);
                    $rdlength = pack('n', strlen($rdata));
                    break;
                case 'SRV':
                    list($priority, $weight, $port, $target) = explode(' ', $record['content']);
                    $rdata = pack('n', $priority) . pack('n', $weight) . pack('n', $port) . domainNameToDNSFormat($target);
                    $rdlength = pack('n', strlen($rdata));
                    break;
                // Add other record types as needed
                default:
                    break; // Skip unsupported record types
            }

            if (empty($rdata) || empty($rdlength)) {
                continue; // Skip if RDATA is empty
            }

            // Construct the resource record
            $answerSection .= $namePointer . $type . $class . $ttl . $rdlength . $rdata;
            $answerCount++;
        }

        if ($answerCount == 0) {
            // No records of the requested type, but domain exists
            // Return NOERROR with SOA in the authority section
            $flags = 0x8180; // NOERROR
            $anCount = 0;
            $nsCount = 1;

            // Fetch the SOA record for the domain
            $sql = "SELECT * FROM dns_records WHERE name = :name AND type = 'SOA' LIMIT 1";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([':name' => $domainName]);
            $soaRecord = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($soaRecord) {
                // Construct the SOA record
                $authoritySection = '';

                // Name field: use a pointer to the domain name in the question section
                $namePointer = pack('n', 0xc00c); // Pointer to offset 12

                // Type field
                $type = pack('n', 6); // SOA

                // Class field
                $class = pack('n', 1); // IN

                // TTL field
                $ttl = pack('N', $soaRecord['ttl']);

                // RDATA
                list($mname, $rname, $serial, $refresh, $retry, $expire, $minimum) = explode(' ', $soaRecord['content']);
                $rdata = domainNameToDNSFormat($mname) . domainNameToDNSFormat($rname) . pack('N', $serial) . pack('N', $refresh) . pack('N', $retry) . pack('N', $expire) . pack('N', $minimum);
                $rdlength = pack('n', strlen($rdata));

                // Construct the resource record
                $authoritySection .= $namePointer . $type . $class . $ttl . $rdlength . $rdata;
            } else {
                // SOA record not found, cannot construct authority section
                $authoritySection = '';
                $nsCount = 0;
            }

            // Construct the response header
            $responseHeader = $transactionId . pack('n', $flags) . pack('nnnn', $qdCount, $anCount, $nsCount, $arCount);

            // Construct the response
            $response = $responseHeader . $questionSection . $authoritySection;

            // Send the response
            $server->sendto($clientInfo['address'], $clientInfo['port'], $response);
            $pool->put($pdo);
            return;
        }

        // Update the answer count
        $anCount = $answerCount;

        // Construct the response header
        $responseHeader = $transactionId . pack('n', $flags) . pack('nnnn', $qdCount, $anCount, $nsCount, $arCount);

        // Construct the response
        $response = $responseHeader . $questionSection . $answerSection;

        // Send the response
        $server->sendto($clientInfo['address'], $clientInfo['port'], $response);

    } catch (Exception $e) {
        // Log the exception and send a server failure response
        error_log('Error handling DNS query: ' . $e->getMessage());
        $flags = 0x8182; // Server failure
        $response = $transactionId . pack('n', $flags) . pack('nnnn', $qdCount, 0, 0, 0) . $questionSection;
        $server->sendto($clientInfo['address'], $clientInfo['port'], $response);
    } finally {
        // Return the PDO connection to the pool
        $pool->put($pdo);
    }

});

// Start the server
$server->start();

function domainNameToDNSFormat($domainName) {
    $labels = explode('.', $domainName);
    $dnsFormat = '';
    foreach ($labels as $label) {
        $length = strlen($label);
        if ($length > 63) {
            // Label too long, skip
            continue;
        }
        $dnsFormat .= chr($length) . $label;
    }
    $dnsFormat .= "\x00"; // End of the domain name
    return $dnsFormat;
}

function parseDomainName($data, &$offset) {
    $labels = [];
    $jumped = false;
    $originalOffset = $offset;
    while (true) {
        if (!isset($data[$offset])) {
            // End of data reached unexpectedly
            return '';
        }
        $length = ord($data[$offset]);
        if ($length == 0) {
            $offset++;
            break;
        }
        if (($length & 0xC0) == 0xC0) {
            // Pointer to another part of the message
            $byte1 = ord($data[$offset]);
            $byte2 = ord($data[$offset + 1]);
            $pointer = (($byte1 & 0x3F) << 8) | $byte2;
            if (!$jumped) {
                $offset += 2;
            }
            $offsetCopy = $pointer;
            $labels[] = parseDomainName($data, $offsetCopy);
            break;
        } else {
            $offset++;
            $labels[] = substr($data, $offset, $length);
            $offset += $length;
        }
    }
    return implode('.', $labels);
}
