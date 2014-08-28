#!/usr/bin/python2
# -*- coding: utf-8 -*-
try:
    from PIL import Image
except:
    import Image
import sys
from cStringIO import StringIO
import time

bash = False
width = 0
height = 0
imgWidth = 0
imgHeight = 0
character = u'▄'
verbose = False
native = "_xterm256.c"

CUBE_STEPS = [0x00, 0x5F, 0x87, 0xAF, 0xD7, 0xFF]
BASIC16 = ((0, 0, 0), (205, 0, 0), (0, 205, 0), (205, 205, 0),
           (0, 0, 238), (205, 0, 205), (0, 205, 205), (229, 229, 229),
           (127, 127, 127), (255, 0, 0), (0, 255, 0), (255, 255, 0),
           (92, 92, 255), (255, 0, 255), (0, 255, 255), (255, 255, 255))

def usage():
    print("\n  "+sys.argv[0]+" [-whcbvn] image")
    print("  Options:")
    print("  -w --width          - width in pixels, if specified without height, the image")
    print("                        will be scaled proportionally")
    print("  -h --height         - see width")
    print("  -c --character      - character to use for foreground")
    print("  -b --as-bash-script - output is a bash script")
    print("  -v --verbose        - verbose output")
    print("  -n --native         - name of the C-file which will be used to replace xterm_to_rgb")
    print("                        and rgb_to_xterm by native methods")
    print("  --help              - this")
    print("  image               - Any image or gif (output will be animated)\n")

def xterm_to_rgb(xcolor):
    assert 0 <= xcolor <= 255
    if xcolor < 16:
        # basic colors
        return BASIC16[xcolor]
    elif 16 <= xcolor <= 231:
        # color cube
        xcolor -= 16
        return (CUBE_STEPS[(xcolor / 36) % 6],
                CUBE_STEPS[(xcolor / 6) % 6],
                CUBE_STEPS[xcolor % 6])
    elif 232 <= xcolor <= 255:
        # gray tone
        c = 8 + (xcolor - 232) * 0x0A
        return (c, c, c)

COLOR_TABLE = [xterm_to_rgb(i) for i in xrange(256)]

def rgb_to_xterm(r, g, b):
    if r < 5 and g < 5 and b < 5:
        return 16
    best_match = 0
    smallest_distance = 10000000000
    for c in xrange(16, 256):
        d = (COLOR_TABLE[c][0] - r) ** 2 + \
            (COLOR_TABLE[c][1] - g) ** 2 + \
            (COLOR_TABLE[c][2] - b) ** 2
        if d < smallest_distance:
            smallest_distance = d
            best_match = c
    return best_match

def printPixels(rgb1,rgb2):
    c1 = rgb_to_xterm(rgb1[0], rgb1[1],rgb1[2])
    c2 = rgb_to_xterm(rgb2[0], rgb2[1],rgb2[2])
    sys.stdout.write('\x1b[48;5;%d;38;5;%dm' % (c1, c2))
    sys.stdout.write(character)

def printImage(im):
    global line
    for y in range(0,height-1,2):
        for x in range(width):
            p1 = im.getpixel((x,y))
            p2 = im.getpixel((x,y+1))
            printPixels(p1, p2)
        print('\x1b[0m')

def iterateImages(im):
    if bash:
        print("echo '\x1b[s'")
    else:
        sys.stdout.write('\x1b[s')

    while True:
        if bash:
            print('cat <<"EOF"')
        sys.stdout.write('\x1b[u')
        printImage(getFrame(im))
        if bash:
            print("EOF")

        try:
            im.seek(im.tell()+1)
            if bash:
                print('sleep '+str(im.info['duration']/1000.0))
            else:
                time.sleep(im.info['duration']/1000.0)
        except EOFError:
            break

def getFrame(im):
        if width!=imgWidth or height!=imgHeight:
            return im.resize((width,height), Image.ANTIALIAS).convert('RGB')
        else:
            return im.convert('RGB')

def compile_speedup():
    import os
    import ctypes
    from os.path import join, dirname, getmtime, exists, expanduser
    # library = join(dirname(__file__), '_xterm256.so')
    library = expanduser('~/.xterm256.so')
    sauce = join(dirname(__file__), native)
    if not exists(library) or getmtime(sauce) > getmtime(library):
        build = "gcc -fPIC -shared -o %s %s" % (library, sauce)
        assert os.system(build + " >/dev/null 2>&1") == 0
    xterm256_c = ctypes.cdll.LoadLibrary(library)
    xterm256_c.init()
    def xterm_to_rgb(xcolor):
        res = xterm256_c.xterm_to_rgb_i(xcolor)
        return ((res >> 16) & 0xFF, (res >> 8) & 0xFF, res & 0xFF)
    return (xterm256_c.rgb_to_xterm, xterm_to_rgb)


def show(img):
    jpeg_data = StringIO(img)
    im = Image.open(jpeg_data)
    imgWidth = im.size[0]
    imgHeight = im.size[1]
    global width
    global height

    try:
        (rgb_to_xterm, xterm_to_rgb) = compile_speedup()
    except:
        if verbose and not bash:
            print("Failed to compile code, no speedup")
    """
    if width!=0 or height!=0:
        if width==0:
            width=int(imgWidth*(height/float(imgHeight)))
        if height==0:
            height=int(imgHeight*(width/float(imgWidth)))
    else:
        width = imgWidth/2
        height = imgHeight/2
    """
    width = imgWidth/2
    height = imgHeight/2
    iterateImages(im)
