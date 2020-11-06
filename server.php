<?php
class WebSocket {
    const LISTEN_SOCKET_NUM = 9;
	private $master;// 连接 server 的 client
    private $sockets = [];// 不同状态的 socket 管理


    public function __construct($host, $port) {
		
		// 建立一个 socket 套接字
        $this->master = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
        socket_set_option($this->master, SOL_SOCKET, SO_REUSEADDR, 1);
        socket_bind($this->master, $host, $port);
        socket_listen($this->master, self::LISTEN_SOCKET_NUM);
        $this->sockets[0] = ['resource' => $this->master];
		
		// 获取当前用户信息
        $pid = get_current_user();
		
        while (true) {
            $this->doServer();
        }
    }

	// 客户端连接
	private function connect($socket) {
		
		// 获取与套接字关联的外地协议地址
        socket_getpeername($socket, $ip, $port);
		
        $socket_info = [
            'resource' => $socket,
            'uname' => '',
            'handshake' => false,
            'ip' => $ip,
            'port' => $port,
        ];
        $this->sockets[(int)$socket] = $socket_info;
    }

	// 客户端断开连接
    private function disconnect($socket) {
		
		// 返回断开连接的客户端的相关的信息
        $recv_message = [
            'type' => 'disconnect',
            'content' => $this->sockets[(int)$socket]['uname'],
        ];
        unset($this->sockets[(int)$socket]);
        return $recv_message;
    }
	
    private function doServer() {
        $write = NULL;
	    $except = NULL;
        $sockets = array_column($this->sockets, 'resource');
        $read_num = socket_select($sockets, $write, $except, NULL);
		
        foreach ($sockets as $socket) {
			
			// 连接主机的 client 
            if ($socket == $this->master) {
                $client = socket_accept($this->master);
                if (false === $client) {
                    continue;
                } else {
					
					// 连接客户端
                    $this->connect($client);
                    continue;
                }
            } 
			else {
                $bytes = @socket_recv($socket, $buffer, 2048, 0);
                if ($bytes < 9) {
                    $recv_message = $this->disconnect($socket);
                } else {
					 // 如果没有握手，先握手
                    if (!$this->sockets[(int)$socket]['handshake']) {
                        $this->handShake($socket, $buffer);
                        continue;
                    } else {
						 // 如果已经握手，直接解析数据
                        $recv_message = $this->parse($buffer);
                    }
                }
				
				// 插入元素
                array_unshift($recv_message, 'receive_message');
				// 处理数据
                $message = $this->dealMessage($socket, $recv_message);
				// 广播数据
                $this->broadcast($message);
           }
        }
    }

	// 提取 Sec-WebSocket-Key 信息
	private function getKey($req) {
           $key = substr($req, strpos($req, 'Sec-WebSocket-Key:') + 18);
           $key2 = trim(substr($key, 0, strpos($key, "\r\n")));
           return $key2;
    }
	
	// 加密 Sec-WebSocket-Key
    private function encry($req){
           $key = $this->getKey($req);
           echo $key;
           return base64_encode(sha1($key . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11', true));
    }
	
	// 应答 Sec-WebSocket-Accept
    private function handShake($socket, $buffer) {
		
		// 获取加密key
        $acceptKey = $this->encry($buffer);
		echo $acceptKey;
		$upgrade = "HTTP/1.1 101 Switching Protocols\r\n" .
                   "Upgrade: websocket\r\n" .
                   "Connection: Upgrade\r\n" .
                   "Sec-WebSocket-Accept: " . $acceptKey . "\r\n" .
                   "\r\n";
		
		// 向socket里写入信息
        socket_write($socket, $upgrade, strlen($upgrade));
        $this->sockets[(int)$socket]['handshake'] = true;
        socket_getpeername($socket, $ip, $port);

        $message = [
            'type' => 'handshake',
            'content' => 'done',
        ];
        $message = $this->buildFrame(json_encode($message));
        socket_write($socket, $message, strlen($message));
        return true;
    }

	// 解析客户端发送来的数据
    private function parse($buffer) {
        $decoded = '';
        $len = ord($buffer[1]) & 127;
        if ($len === 126) {
            $masks = substr($buffer, 4, 4);
            $data = substr($buffer, 8);
        } else if ($len === 127) {
            $masks = substr($buffer, 10, 4);
            $data = substr($buffer, 14);
        } else {
            $masks = substr($buffer, 2, 4);
            $data = substr($buffer, 6);
        }
        for ($index = 0; $index < strlen($data); $index++) {
            $decoded .= $data[$index] ^ $masks[$index % 4];
        }

        return json_decode($decoded, true);
    }
	
	// 创建 websocket 数据帧
    private function buildFrame($message) {
        $frame = [];
        $frame[0] = '81';
        $len = strlen($message);
        if ($len < 126) {
            $frame[1] = $len < 16 ? '0' . dechex($len) : dechex($len);
        } else if ($len < 65025) {
            $s = dechex($len);
            $frame[1] = '7e' . str_repeat('0', 4 - strlen($s)) . $s;
        } else {
            $s = dechex($len);
            $frame[1] = '7f' . str_repeat('0', 16 - strlen($s)) . $s;
        }

        $data = '';
        $l = strlen($message);
        for ($i = 0; $i < $l; $i++) {
            $data .= dechex(ord($message{$i}));
        }
        $frame[2] = $data;

        $data = implode('', $frame);

        return pack("H*", $data);
    }

    private function dealMessage($socket, $recv_message) {
		
		// 获取数据的类型， login ， disconnect ， user
        $message_type = $recv_message['type'];
		// 获取数据内容
        $message_content = $recv_message['content'];
        $response = [];

        switch ($message_type) {
            case 'login':
				// 存储名字
                $this->sockets[(int)$socket]['uname'] = $message_content;
                // 取得的名字
                $user_list = array_column($this->sockets, 'uname');
                $response['type'] = 'login';
                $response['content'] = $message_content;
                $response['user_list'] = $user_list;
                break;
            case 'disconnect':
                $user_list = array_column($this->sockets, 'uname');
                $response['type'] = 'disconnect';
                $response['content'] = $message_content;
                $response['user_list'] = $user_list;
                break;
            case 'user':
                $uname = $this->sockets[(int)$socket]['uname'];
                $response['type'] = 'user';
                $response['from'] = $uname;
                $response['content'] = $message_content;
                break;
        }
        
		// 返回创建的 websocket 数据帧
        return $this->buildFrame(json_encode($response));
    }

	// 广播
    private function broadcast($data) {
        foreach ($this->sockets as $socket) {
            if ($socket['resource'] == $this->master) {
                continue;
            }
            socket_write($socket['resource'], $data, strlen($data));
        }
    }

}

$ws = new WebSocket("127.0.0.1", "4000");