gcc -o bserver `pkg-config --cflags glib-2.0` `pkg-config --cflags gnome-keyring-1` bserver.c -o bserver `pkg-config --libs glib-2.0` `pkg-config --libs gnome-keyring-1` -lssl -lcrypto
g++ -std=c++11 bclient.cpp -o bclient -lssl -lcrypto
