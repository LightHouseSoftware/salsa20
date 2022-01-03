module salsa20;

enum SALSA_KEY_LENGTH
{
	BIT_256,
	BIT_128
};

enum SALSA_STATUS 
{
	OK,
	ERROR
};

class Salsa20
{
	private @system @nogc
	{
		static uint rotateLeft(uint value, int shift) 
		{
			return (value << shift) | (value >> (32 - shift));
		}
		
		static void quarterRound(uint* y0, uint* y1, uint* y2, uint* y3)
		{
			*y1 = *y1 ^ rotateLeft(*y0 + *y3, 7);
			*y2 = *y2 ^ rotateLeft(*y1 + *y0, 9);
			*y3 = *y3 ^ rotateLeft(*y2 + *y1, 13);
			*y0 = *y0 ^ rotateLeft(*y3 + *y2, 18);
		}
		
		static void rowRound(uint* y)
		{
			quarterRound(&y[0], &y[1], &y[2], &y[3]);
			quarterRound(&y[5], &y[6], &y[7], &y[4]);
			quarterRound(&y[10], &y[11], &y[8], &y[9]);
			quarterRound(&y[15], &y[12], &y[13], &y[14]);
		}
		
		static void columnRound(uint* x)
		{
			quarterRound(&x[0], &x[4], &x[8], &x[12]);
			quarterRound(&x[5], &x[9], &x[13], &x[1]);
			quarterRound(&x[10], &x[14], &x[2], &x[6]);
			quarterRound(&x[15], &x[3], &x[7], &x[11]);
		}
		
		static void doubleRound(uint* x)
		{
			columnRound(x);
			rowRound(x);
		}
		
		static uint littleEndian(ubyte* b)
		{
			return b[0] + ushort(b[1] << 8) + uint(b[2] << 16) + uint(b[3] << 24);
		}
		
		static void reverseLittleEndian(ubyte* b, uint w)
		{
			b[0] = cast(ubyte) w;
			b[1] = cast(ubyte) (w >> 8);
			b[2] = cast(ubyte) (w >> 16);
			b[3] = cast(ubyte) (w >> 24);
		}
	}
	
	static void hash(ubyte* seq) @system @nogc
	{
		int i;
		uint[16] x;
		uint[16] z;
		
		for (i = 0; i < 16; ++i)
		{
			x[i] = z[i] = littleEndian(seq + (4 * i));
	    }
	    
	    for (i = 0; i < 10; ++i)
	    {
			doubleRound(z.ptr);
	    }
	    
	    for (i = 0; i < 16; ++i) 
	    {
			z[i] += x[i];
			reverseLittleEndian(seq + (4 * i), z[i]);
	    }
	}
	
	static void expand16(ubyte* k, ubyte* n, ubyte* keystream) @system @nogc
	{
		int i, j;
		
		ubyte[4][4] t = [
			[ 'e', 'x', 'p', 'a' ],
			[ 'n', 'd', ' ', '1' ],
			[ '6', '-', 'b', 'y' ],
			[ 't', 'e', ' ', 'k' ]
	    ];
	    
	    for (i = 0; i < 64; i += 20)
	    {
			for (j = 0; j < 4; ++j)
			{
				keystream[i + j] = t[i / 20][j];
	        }
	    }
	    
	    for (i = 0; i < 16; ++i) 
	    {
			keystream[4+i]  = k[i];
			keystream[44+i] = k[i];
			keystream[24+i] = n[i];
	    }
	    
	    hash(keystream);
	}
	
	static void expand32(ubyte* k, ubyte* n, ubyte* keystream) @system @nogc
	{
		int i, j;
		
		ubyte[4][4] o = [
			[ 'e', 'x', 'p', 'a' ],
			[ 'n', 'd', ' ', '3' ],
			[ '2', '-', 'b', 'y' ],
			[ 't', 'e', ' ', 'k' ]
	    ];
	    
	    for (i = 0; i < 64; i += 20)
	    {
			for (j = 0; j < 4; ++j) 
			{
				keystream[i + j] = o[i / 20][j];
			}
	    }
	    
	    for (i = 0; i < 16; ++i) 
	    {
			keystream[4+i]  = k[i];
			keystream[44+i] = k[i+16];
			keystream[24+i] = n[i];
	    }
	    
	    hash(keystream);
	}
	
	SALSA_STATUS crypt(ubyte* key, SALSA_KEY_LENGTH keylen, ubyte* nonce, uint si, ubyte* buf, uint buflen) @system @nogc
	{
		ubyte[64] keystream;
		ubyte[16] n = 0;
	    uint i;
	
	    @system @nogc void function(ubyte* k, ubyte* n, ubyte* keystream) expand; 
	  
	    if (keylen == SALSA_KEY_LENGTH.BIT_256)
	    {
			expand = &this.expand32;
		}
	    
	    if (keylen == SALSA_KEY_LENGTH.BIT_128)
	    {
			expand = &this.expand16;
		}
		
		if ((expand == null) || (key == null) || (nonce == null) || (buf == null))
		{
			return SALSA_STATUS.ERROR;
		}
		
		for (i = 0; i < 8; ++i)
		{
			n[i] = nonce[i];
		}
		
		if (si % 64 != 0) 
		{
			reverseLittleEndian(n.ptr + 8, si / 64);
			(*expand)(key, n.ptr, keystream.ptr);
		}
		
		for (i = 0; i < buflen; ++i) 
		{
			if ((si + i) % 64 == 0) 
			{
				reverseLittleEndian(n.ptr + 8, ((si + i) / 64));
				(*expand)(key, n.ptr, keystream.ptr);
            }

			buf[i] ^= keystream[(si + i) % 64];
        }
	
		return SALSA_STATUS.OK;
	}
	
	this()
	{
		
	}
}
