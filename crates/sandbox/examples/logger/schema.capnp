@0xefdfd22cb517ca19;

struct Message {
    queryName @0 :Data;
    queryType @1 :UInt16;
    protocol @2 :Protocol;
}

enum Protocol {
	udp   @0;
	tcp   @1;
	tls   @2;
	https @3;
}