#include <QCoreApplication>
#include <QImage>
#include <iostream>

/**
This challenge had a list of what appeared to be RGB values in a text file. After some initial
playing around, I discovered the number of pixels is 528601. It has only 2 factors: 929 and 569.

Incidentally, I first incorrectly decided there were 528600 pixels.  When that actored it had a
single large factor like 881, and a bunch of other smaller factors.  But of course I ran into
a bunch of issues trying to get that to work.

Just feed the data into this application using stdin

After the CTF I learned that Python has a image library that knocked this challenge out a lot
easier than my implementation
*/

uint32_t justTheNumber(std::string numberWithGarbage)
{
    std::string withoutGarbage;
    for(auto singleChar : numberWithGarbage)
    {
        if ( (singleChar >= '0') && (singleChar <= '9'))
        {
            withoutGarbage += singleChar;
        }
    }

    return strtol(withoutGarbage.c_str(), NULL, 10);
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    const int NUM_PIXELS = 528601;
    const int WIDTH_PIXELS = 929; // 929, 569
    const int HEIGHT_PIXELS = NUM_PIXELS / WIDTH_PIXELS;
    QImage pic(WIDTH_PIXELS, HEIGHT_PIXELS, QImage::Format_RGB32);

    int x = 0;
    int y = 0;
    int i = 0;
    while(i < NUM_PIXELS)
    {
       std::string r, g, b;
       std::cin >> r >> g >> b;

       uint32_t rVal = justTheNumber(r);
       uint32_t gVal = justTheNumber(g);
       uint32_t bVal = justTheNumber(b);

       uint32_t value = 0xff000000;
       value = value | (rVal << 16);
       value = value | (gVal << 8);
       value = value | (bVal << 0);

       std::cout << i << "@" << x << ", " << y << "    " << "(rgb = " << r << ", " << g << ", " << b << ") = (" << rVal << ", " << gVal << ", " << bVal << ")" << std::endl;

       pic.setPixel(x,y,value);


       x++;
       if (x == WIDTH_PIXELS)
       {
           y++;
           x = 0;
       }
       i++;
    }

    pic.save("output.png", "PNG");
    std::cout << "Image Dimensions: (" << WIDTH_PIXELS << ", " << HEIGHT_PIXELS << ")" << std::endl;

    return 0;

    return a.exec();
}
