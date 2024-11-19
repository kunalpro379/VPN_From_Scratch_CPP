#ifndef TUNNELING_HPP
#define TUNNELING_HPP
#include <string>

class Tunneling{
     public:
     ///Constructor
     Tunneling();
     //to encapsulate data for tunneling
     string tunnelingEncapsulation();
     //to decapsulate  recived tunneled data

     private:
     string addHeader();
     string removeHeader();
};
#endif