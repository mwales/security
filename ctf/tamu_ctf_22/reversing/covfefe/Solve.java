public class Solve
{
	static public void main(String[] args)
	{
		System.out.println("Hello World\n");
		chal();
	}

	static public void chal()
	{
    byte b1 = 35;
    int[] arrayOfInt = new int[b1];
    byte b2;
    for (b2 = 0; b2 < b1; b2++)
      arrayOfInt[b2] = 0; 
    arrayOfInt[0] = 103;
    arrayOfInt[1] = arrayOfInt[0] + 2;
    arrayOfInt[2] = arrayOfInt[0];
    for (b2 = 3; b2 < 8; b2++) {
      switch (b2) {
        case 3:
          arrayOfInt[b2] = 101;
          break;
        case 4:
          arrayOfInt[6] = 99;
          break;
        case 5:
          arrayOfInt[5] = 123;
          break;
        case 6:
          arrayOfInt[b2 + 1] = 48;
          break;
        case 7:
          arrayOfInt[4] = 109;
          break;
      } 
    } 
    arrayOfInt[8] = 102;
    arrayOfInt[9] = arrayOfInt[8];
    arrayOfInt[28] = arrayOfInt[7];
    arrayOfInt[25] = arrayOfInt[7];
    arrayOfInt[24] = arrayOfInt[7];
    arrayOfInt[10] = 51;
    arrayOfInt[11] = arrayOfInt[10] + 12 - 4 - 4 - 4;
    arrayOfInt[27] = arrayOfInt[0] - (int)Math.pow(2.0D, 3.0D);
    arrayOfInt[22] = arrayOfInt[0] - (int)Math.pow(2.0D, 3.0D);
    arrayOfInt[15] = arrayOfInt[0] - (int)Math.pow(2.0D, 3.0D);
    arrayOfInt[12] = arrayOfInt[0] - (int)Math.pow(2.0D, 3.0D);
    arrayOfInt[13] = 49;
    arrayOfInt[14] = 115;
    for (b2 = 16; b2 < 22; b2++) {
      switch (b2) {
        case 16:
          arrayOfInt[b2 + 1] = 108;
          break;
        case 17:
          arrayOfInt[b2 - 1] = 52;
          break;
        case 18:
          arrayOfInt[b2 + 1] = 52;
          break;
        case 19:
          arrayOfInt[b2 - 1] = 119;
          break;
        case 20:
          arrayOfInt[b2 + 1] = 115;
          break;
        case 21:
          arrayOfInt[b2 - 1] = 121;
          break;
      } 
    } 
    arrayOfInt[23] = 103;
    arrayOfInt[26] = arrayOfInt[23] - 3;
    arrayOfInt[29] = arrayOfInt[26] + 20;
    arrayOfInt[30] = arrayOfInt[29] % 53 + 53;
    arrayOfInt[31] = arrayOfInt[0] - 18;
    arrayOfInt[32] = 80;
    arrayOfInt[33] = 83;
    arrayOfInt[b1 - 1] = (int)Math.pow(5.0D, 3.0D);

	for(int i = 0; i < 35; i++)

	{
		System.out.print((char)arrayOfInt[i]);
	}

	System.out.println("");
	}
}

