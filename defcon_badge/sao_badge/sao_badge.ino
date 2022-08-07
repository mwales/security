/**************************************************************************
 * Things to display.
 * - Ukraine flag / slava ukraine
 * - boot force
 * - giant boot
 * - shooter game shooting planes
 * - ghost of kyiv
 **************************************************************************/

#include <SPI.h>
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

#define SCREEN_WIDTH 128 // OLED display width, in pixels
#define SCREEN_HEIGHT 64 // OLED display height, in pixels

// Declaration for an SSD1306 display connected to I2C (SDA, SCL pins)
// The pins for I2C are defined by the Wire-library. 
// On an arduino UNO:       A4(SDA), A5(SCL)
// On an arduino MEGA 2560: 20(SDA), 21(SCL)
// On an arduino LEONARDO:   2(SDA),  3(SCL), ...
#define OLED_RESET     -1 // Reset pin # (or -1 if sharing Arduino reset pin)
#define SCREEN_ADDRESS 0x3c ///< See datasheet for Address; 0x3D for 128x64, 0x3C for 128x32
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);

#define NUMFLAKES     10 // Number of snowflakes in the animation example

#define LOGO_HEIGHT   16
#define LOGO_WIDTH    16
static const unsigned char PROGMEM logo_bmp[] =
{
	0b00000000, 0b11000000,
	0b00000001, 0b11000000,
	0b00000001, 0b11000000,
	0b00000011, 0b11100000,
	0b11110011, 0b11100000,
	0b11111110, 0b11111000,
	0b01111110, 0b11111111,
	0b00110011, 0b10011111,
	0b00011111, 0b11111100,
	0b00001101, 0b01110000,
	0b00011011, 0b10100000,
	0b00111111, 0b11100000,
	0b00111111, 0b11110000,
	0b01111100, 0b11110000,
	0b01110000, 0b01110000,
	0b00000000, 0b00110000
};



void setup()
{
	Serial.begin(9600);
	 
	// SSD1306_SWITCHCAPVCC = generate display voltage from 3.3V internally
	if(!display.begin(SSD1306_SWITCHCAPVCC, SCREEN_ADDRESS))
	{
		Serial.println(F("SSD1306 allocation failed"));
		for(;;); // Don't proceed, loop forever
	}
	 
	// Show initial display buffer contents on the screen --
	// the library initializes this with an Adafruit splash screen.
	display.clearDisplay();

	// My display is inverted on the badge
	//display.ssd1306_command(SSD1306_SEGREMAP);
	//display.ssd1306_command(SSD1306_COMSCANINC);
	display.setRotation(2);
	display.setTextWrap(false);
}

uint8_t demoState = 0;
uint16_t demoFrame = 0;
#define FRAME_SCALAR 4

void loop()
{
	switch(demoState)
	{
	case 0:
		runJavelinIntroState();
		break;
	case 1:
		runTankRollState();
		break;
	case 2:
		runJavelinFireState();
		break;
	case 3:
		runTankFireState();
		break;
	case 4:
		runJackBoxState();
		break;
	case 5:
		runBootForceDiskState();
		break;
	case 6:
		runSlavaUkraineState();
		break;
	case 7:
		runGhostOfKyivState();
		break;
	case 8:
		runFlagState();
		break;
	default:
		Serial.println("State machine restart!");
		demoState = 0;
		demoFrame = 0;
		return;
	}

	uint32_t curFrame = millis() >> FRAME_SCALAR;
	while(curFrame == millis() >> FRAME_SCALAR)
	{
		// nothing  
	}

	//Serial.print(".");
	demoFrame++;
}

void runFlagState()
{
	display.invertDisplay(false);
	display.clearDisplay();

	drawFlag(40, 32);

	display.display();

	if (demoFrame > 100)
	{
		Serial.println("End of flag state");
		demoFrame = 0xffff;
		demoState++;
	}
}

void runCircleState()
{
	if (demoFrame == 0)
	{
		display.clearDisplay();
	}

	if (demoFrame > max(display.width() >> 1, display.height() >> 1) )
	{
		if (demoFrame > 100)
		{
			// Start over state machine
			Serial.println("Restart state machine");
			demoFrame = 0xffff;
			demoState++;
			return;
		}
	}

	display.fillCircle(display.width() / 2, display.height() / 2, demoFrame, SSD1306_INVERSE);
	display.display(); // Update screen with each newly-drawn circle
}

void runSlavaUkraineState()
{
	if (demoFrame == 0)
	{
		display.clearDisplay();
		display.setTextSize(2);
		display.setTextColor(SSD1306_WHITE);
		display.invertDisplay(false);

		drawFlag(40,32);
	}
	else
	{
		// Delete the last frame's text
		for(int row = 10; row < 30; row++)
		{
			display.drawFastHLine(0,row,128, SSD1306_BLACK);
		}
	}


	display.setCursor(128 - (demoFrame << 1), 10);
	display.print(F("Slava Ukraini"));
	
	
	display.display();      // Show initial text

	if (demoFrame > 150)
	{
		Serial.println("End of slava ukraine state");
		demoFrame = 0xffff;
		demoState++;
	}
}

#define MIG29_WIDTH 16
#define MIG29_HEIGHT 15
static const unsigned char PROGMEM mig29bmp[] =
{
	0b00011000, 0b00000000,
	0b00010100, 0b00000000,
	0b00010010, 0b00000000,
	0b10001001, 0b00000000,
	0b11001000, 0b10000000,
	0b11110111, 0b11110000,
	0b01001000, 0b00001110,
	0b01110000, 0b00010001,
	0b01001000, 0b00001110,
	0b11110111, 0b11110000,
	0b11001000, 0b10000000,
	0b10001001, 0b00000000,
	0b00010010, 0b00000000,
	0b00010100, 0b00000000,
	0b00011000, 0b00000000,
};



void runGhostOfKyivState()
{
	if (demoFrame == 0)
	{
		display.invertDisplay(true);
		display.clearDisplay();
		display.setTextSize(2);
		display.setTextColor(SSD1306_WHITE);
		return;
	}
	
	// Animation frames
	if (demoFrame < 150)
	{
		// Delete the last frame's text
		for(int row = 4; row < 20; row++)
		{
			display.drawFastHLine(0,row,SCREEN_WIDTH, SSD1306_BLACK);
		}
	
		display.drawBitmap(demoFrame - 20, 4, mig29bmp, MIG29_WIDTH, MIG29_HEIGHT, SSD1306_WHITE);  
	
		if (demoFrame < 100)
		{
			// Animate Ghost too
			display.setCursor(demoFrame - 80, 6);
		}
		else
		{
			display.setCursor(20, 6);
		}

		display.print("GHOST");
		display.display();      // Show initial text
	}

	if (demoFrame == 150)
	{
		display.setCursor(55, 28);
		display.print("OF");

		display.setCursor(65, 49);
		display.print("KYIV");
		display.display();
	}

	if (demoFrame > 400)
	{
		Serial.println("End of ghost of kyiv state");
		demoFrame = 0xffff;
		demoState++;
	}
}


#define BOOT_DISK_WIDTH 32
#define BOOT_DISK_HEIGHT 31
static const unsigned char PROGMEM bootdiskbmp[] =
{
	0b11111111, 0b11111111, 0b11111111, 0b11111111,
	0b10000000, 0b00000000, 0b00000000, 0b00000001,
	0b10010000, 0b00111001, 0b00110011, 0b10111001,
	0b10011111, 0b00100010, 0b10101010, 0b00100001,
	0b10010000, 0b00110010, 0b10110010, 0b00110001,
	0b10001110, 0b00100001, 0b00101011, 0b10111001,
	0b11010001, 0b00000000, 0b00000000, 0b00000011,
	0b01001110, 0b00000000, 0b00000000, 0b00000010,
	0b11000000, 0b00000000, 0b00000000, 0b00000011,
	0b10001110, 0b00000000, 0b00000000, 0b00000001,
	0b10010001, 0b00000011, 0b11000000, 0b00000001,
	0b10001110, 0b00000100, 0b00100000, 0b00000001,
	0b10000000, 0b00001001, 0b10010000, 0b00000001,
	0b10001010, 0b00001010, 0b01010000, 0b00000001,
	0b10010101, 0b00001010, 0b01010000, 0b00000001,
	0b10011111, 0b00001001, 0b10010000, 0b00000001,
	0b00000000, 0b00000100, 0b00100000, 0b00000001,
	0b10000000, 0b00000011, 0b11000100, 0b00000001,
	0b10000000, 0b00000000, 0b00001010, 0b00000001,
	0b10000000, 0b00000000, 0b00000100, 0b00000001,
	0b10000000, 0b00000001, 0b10000000, 0b00000001,
	0b10000000, 0b00000010, 0b01000000, 0b00000001,
	0b10000000, 0b00000010, 0b01000000, 0b00000001,
	0b10000000, 0b00000010, 0b01000000, 0b00000001,
	0b10000000, 0b00000010, 0b01000000, 0b00000001,
	0b10000000, 0b00000010, 0b01000000, 0b00000001,
	0b10000000, 0b00000010, 0b01000000, 0b00000001,
	0b10000000, 0b00000010, 0b01000000, 0b00000001,
	0b10000000, 0b00000001, 0b10000000, 0b00000001,
	0b10000000, 0b00000000, 0b00000000, 0b00000001,
	0b11111111, 0b11111111, 0b11111111, 0b11111111,
};


void runBootForceDiskState()
{
	if (demoFrame == 0)
	{
		display.invertDisplay(false);
		display.clearDisplay();
		display.setTextSize(2);
		display.setTextColor(SSD1306_WHITE);
		return;
	}
	
	// Animation frames
	if (demoFrame < 40)
	{
		
		// Delete the last frame's text
		display.clearDisplay();

		display.drawBitmap(SCREEN_WIDTH / 2 - BOOT_DISK_WIDTH / 2, demoFrame - BOOT_DISK_HEIGHT, 
		                   bootdiskbmp, BOOT_DISK_WIDTH, BOOT_DISK_HEIGHT, SSD1306_WHITE);  
	
		display.display();
	}

	if (demoFrame == 40)
	{
		display.setCursor(24, 20);
		display.print("i");
		display.setCursor(90, 20);
		display.print("am");
		display.setCursor(5, 48);
		display.print("boot_force");
		display.display();
	}

	if (demoFrame > 700)
	{
		Serial.println("End of boot force state");
		demoFrame = 0xffff;
		demoState++;
	}
}



#define JAVELIN_WIDTH 24
#define JAVELIN_HEIGHT 14
static const unsigned char PROGMEM javelinbmp[] =
{
	0b01110000, 0b00000000, 0b00000000,
	0b01001111, 0b00000000, 0b00000000,
	0b11000000, 0b11110000, 0b00001100,
	0b10000111, 0b00001111, 0b00010010,
	0b11111000, 0b10000000, 0b11111011,
	0b00001000, 0b10000000, 0b00001001,
	0b00101000, 0b11110000, 0b00001011,
	0b00110000, 0b10001111, 0b00010010,
	0b00100001, 0b00000000, 0b11110010,
	0b00100001, 0b00000000, 0b01000100,
	0b00111001, 0b00000000, 0b00111000,
	0b00101111, 0b00000000, 0b00000000,
	0b00000110, 0b00000000, 0b00000000,
	0b00000110, 0b00000000, 0b00000000,
};

void runJavelinIntroState()
{
	if (demoFrame == 0)
	{
		display.invertDisplay(false);
		display.clearDisplay();
		display.setTextSize(2);
		display.setTextColor(SSD1306_WHITE);
		return;
	}
	
	// Animation frames
	if (demoFrame < 225)
	{
		// Delete the last frame's text
		display.clearDisplay();

		display.setCursor(140 - demoFrame, 4);
		display.print("Saint");
		display.setCursor(128 - demoFrame, 20);
		display.print("Javelin");
	}

	if (demoFrame < 128)
	{
		display.setCursor(-125 + demoFrame, 48);
		display.print("FGM-148");

		display.drawBitmap(demoFrame - JAVELIN_WIDTH, 48, 
		                   javelinbmp, JAVELIN_WIDTH, JAVELIN_HEIGHT, SSD1306_WHITE);  
	
	}

	if ( (demoFrame >= 128) && (demoFrame < 225) )
	{
		display.setCursor(3, 48 + demoFrame - 128);
		display.print("FGM-148");

		display.drawBitmap(128 - JAVELIN_WIDTH, 48, 
		                   javelinbmp, JAVELIN_WIDTH, JAVELIN_HEIGHT, SSD1306_WHITE);  
	}

	
	display.display();

	if (demoFrame >= 225)
	{
		Serial.println("End of javelin text state");
		demoFrame = 0xffff;
		demoState++;
	}
}

#define T72_WIDTH 32
#define T72_HEIGHT 9
static const unsigned char PROGMEM t72bmp[] =
{
	0b00000000, 0b00111111, 0b11110000, 0b00111000,
	0b00000000, 0b11000000, 0b00001100, 0b11100000,
	0b00000001, 0b00000000, 0b00000011, 0b10000000,
	0b11111111, 0b10000000, 0b00000100, 0b00000000,
	0b11011101, 0b11111111, 0b11111111, 0b11111000,
	0b11101011, 0b00000000, 0b00000000, 0b00001000,
	0b11110111, 0b11111111, 0b11111111, 0b11111000,
	0b00111110, 0b00100010, 0b00100010, 0b00100000,
	0b00011111, 0b11111111, 0b11111111, 0b11000000
};


void runTankRollState()
{
	if (demoFrame == 0)
	{
		display.invertDisplay(false);
		display.clearDisplay();
		display.setTextSize(2);
		display.setTextColor(SSD1306_WHITE);
		return;
	}
	
	// Animation frames
	if (demoFrame < T72_WIDTH + 10)
	{
		// Delete the last frame's text
		display.clearDisplay();

		display.drawBitmap(demoFrame - T72_WIDTH, 55, t72bmp, T72_WIDTH, T72_HEIGHT, SSD1306_WHITE);
		display.drawBitmap(128 - JAVELIN_WIDTH, 48, 
		                   javelinbmp, JAVELIN_WIDTH, JAVELIN_HEIGHT, SSD1306_WHITE);
		display.display();
	}
	

	if (demoFrame >= 225)
	{
		Serial.println("End of tank roll state");
		demoFrame = 0xffff;
		demoState++;
	}
}

#define MISSLE_START_X 96
#define MISSLE_START_Y 50
void runJavelinFireState()
{
	if (demoFrame < 50)
	{
		display.clearDisplay();
		display.drawPixel(MISSLE_START_X - demoFrame,     MISSLE_START_Y - demoFrame,     SSD1306_WHITE);
		display.drawPixel(MISSLE_START_X + 1 - demoFrame, MISSLE_START_Y - demoFrame,     SSD1306_WHITE);
		display.drawPixel(MISSLE_START_X + 2 - demoFrame, MISSLE_START_Y + 1 - demoFrame, SSD1306_WHITE);
		display.drawPixel(MISSLE_START_X + 2 - demoFrame, MISSLE_START_Y - demoFrame,     SSD1306_WHITE);
		display.drawPixel(MISSLE_START_X + 2 - demoFrame, MISSLE_START_Y - 1 - demoFrame,     SSD1306_WHITE);
	}
	else if (demoFrame >= 50)
	{
		display.clearDisplay();
		display.drawPixel(MISSLE_START_X - 50 - (demoFrame >> 3) - 1, MISSLE_START_Y - 100 + demoFrame, SSD1306_WHITE);
		display.drawPixel(MISSLE_START_X - 50 - (demoFrame >> 3) + 1, MISSLE_START_Y - 100 + demoFrame, SSD1306_WHITE);
		display.drawPixel(MISSLE_START_X - 50 - (demoFrame >> 3),     MISSLE_START_Y - 100 + demoFrame, SSD1306_WHITE);
		display.drawPixel(MISSLE_START_X - 50 - (demoFrame >> 3),     MISSLE_START_Y - 99 + demoFrame, SSD1306_WHITE);
		display.drawPixel(MISSLE_START_X - 50 - (demoFrame >> 3),     MISSLE_START_Y - 98 + demoFrame, SSD1306_WHITE);
	}

	display.drawBitmap(10, 55, t72bmp, T72_WIDTH, T72_HEIGHT, SSD1306_WHITE);
	display.drawBitmap(128 - JAVELIN_WIDTH, 48, 
		                   javelinbmp, JAVELIN_WIDTH, JAVELIN_HEIGHT, SSD1306_WHITE);
	display.display();
	
	if (demoFrame >= 100)
	{
		Serial.println("End of javeline fire state");
		demoFrame = 0xffff;
		demoState++;
	}
}

#define FIRE_X 30
#define FIRE_Y 55
void runTankFireState()
{
	display.clearDisplay();

	// draw fire coming from tank
	for(int i = 0; i < (demoFrame % 10) + 5; i++)
	{
		if ( (demoFrame + i) % 2)
		{
			display.drawFastHLine(FIRE_X - i, FIRE_Y - i , (i << 1) + 1, SSD1306_BLACK);
		}
		else
		{
			display.drawFastHLine(FIRE_X - i, FIRE_Y - i , (i << 1) + 1, SSD1306_WHITE);
		}
	}

	display.drawBitmap(10, 55, t72bmp, T72_WIDTH, T72_HEIGHT, SSD1306_WHITE);
	display.drawBitmap(128 - JAVELIN_WIDTH, 48, 
		                   javelinbmp, JAVELIN_WIDTH, JAVELIN_HEIGHT, SSD1306_WHITE);
	display.display();

	if (demoFrame > 100)
	{
		Serial.println("End of tank fire state");
		demoFrame = 0xffff;
		demoState++;
	}
	
}

#define TANK_TOP_RADIUS 8
void runJackBoxState()
{
	display.clearDisplay();

	if (demoFrame < 30)
	{
		// draw tank exploding
		for(int i = demoFrame; i > 0; i-=2)
		{
			display.fillCircle(FIRE_X, FIRE_Y, i, SSD1306_INVERSE);
		}
	}
	
	int16_t centerY;
	if (demoFrame < 50)
	{
		centerY = FIRE_Y - demoFrame;
	}
	else
	{
		centerY = FIRE_Y - 100 + demoFrame;
	}

	// draw tank topper
	display.drawCircle(FIRE_X, centerY, TANK_TOP_RADIUS, SSD1306_WHITE);
	switch(demoFrame % 4)
	{
	case 0:
		display.drawCircle(FIRE_X - 3, centerY - 3, 3, SSD1306_WHITE);
		display.drawCircle(FIRE_X - 3, centerY + 3, 3, SSD1306_WHITE);
		display.drawLine(FIRE_X + TANK_TOP_RADIUS, centerY, FIRE_X + TANK_TOP_RADIUS + 5, centerY, SSD1306_WHITE);
		break;
	
	case 1:
		display.drawCircle(FIRE_X - 3, centerY + 3, 3, SSD1306_WHITE);
		display.drawCircle(FIRE_X + 3, centerY + 3, 3, SSD1306_WHITE);
		display.drawLine(FIRE_X, centerY - TANK_TOP_RADIUS, FIRE_X, centerY - (TANK_TOP_RADIUS + 5), SSD1306_WHITE);
		break;
	
	case 2:
		display.drawCircle(FIRE_X + 3, centerY - 3, 3, SSD1306_WHITE);
		display.drawCircle(FIRE_X + 3, centerY + 3, 3, SSD1306_WHITE);
		display.drawLine(FIRE_X - TANK_TOP_RADIUS, centerY, FIRE_X - (TANK_TOP_RADIUS + 5), centerY, SSD1306_WHITE);
		break;
	
	case 3:
		display.drawCircle(FIRE_X - 3, centerY - 3, 3, SSD1306_WHITE);
		display.drawCircle(FIRE_X + 3, centerY - 3, 3, SSD1306_WHITE);
		display.drawLine(FIRE_X, centerY + TANK_TOP_RADIUS, FIRE_X, centerY + (TANK_TOP_RADIUS + 5), SSD1306_WHITE);
		break;
	}

	display.drawBitmap(10, 58, t72bmp + 12, T72_WIDTH, T72_HEIGHT - 3, SSD1306_WHITE);
	display.drawBitmap(128 - JAVELIN_WIDTH, 48, 
		                   javelinbmp, JAVELIN_WIDTH, JAVELIN_HEIGHT, SSD1306_WHITE);
	display.display();

	if (demoFrame > 100)
	{
		Serial.println("End of jack box state");
		demoFrame = 0xffff;
		demoState++;
	}
	
}


static const unsigned char PROGMEM ukraine_flag[] =
{ 0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111,
  0b11111111, 0b11111111 };


// Flag is 48 pixels wide, 32 pixels tall
void drawFlag(int x, int y)
{
	display.drawBitmap(x,      y,      ukraine_flag, 16, 16, SSD1306_WHITE);  
	display.drawBitmap(x + 16, y,      ukraine_flag, 16, 16, SSD1306_WHITE);  
	display.drawBitmap(x,      y + 16, ukraine_flag, 16, 16, SSD1306_WHITE);  
	display.drawBitmap(x + 16, y + 16, ukraine_flag, 16, 16, SSD1306_WHITE);  
	display.drawBitmap(x + 32, y,      ukraine_flag, 16, 16, SSD1306_WHITE);  
	display.drawBitmap(x + 32, y + 16, ukraine_flag, 16, 16, SSD1306_WHITE);  
}


