# Doublespeak library

Encoding/decoding functions for the [Doublespeak protocol](https://github.com/dblspk/web-app#how-it-works).

## Install

Navigate to the parent directory in your project where you want the library to reside, and clone it into your project as a [submodule](https://github.com/blog/2104-working-with-submodules).
```
cd <project name>
git submodule add https://github.com/dblspk/lib.git lib
```
Thereafter, others who clone your project must do so using the ```--recursive``` option:
```
git clone --recursive <project URL>
```

## Setup

Instantiate the class.
```
var doublespeak = new Doublespeak();
```

## Usage

Call functions from the class like so:
```
var encodedStr = doublespeak.encodeText(str);
```
See the [web app](https://github.com/dblspk/web-app) for example code.

### filterStr
Param: ```String``` str  
Return: ```String```

Remove encoded messages from string.

### encodeText
Param: ```String``` str  
Return: ```String```

Encode plaintext to ciphertext.

### encodeFile
Param: ```String``` type  
Param: ```String``` name  
Param: ```Uint8Array``` bytes  
Return: ```String```

Encode file info and file byte array to ciphertext.

### decodeData
Param: ```String``` str  
Return: ```Object[]``` [{ ```Boolean``` crcMatch, ```Number``` dataType, ```Uint8Array``` data }]

Decode encoded messages in string to array of data objects.

### extractText
Param: ```Uint8Array``` bytes  
Return: ```String```

Convert byte array to [UTF-8](https://en.wikipedia.org/wiki/UTF-8) text.

### extractFile
Param: ```Uint8Array``` bytes  
Return: ```Object``` { ```String``` name, ```Number``` type, ```String``` url, ```Number``` size }

Convert byte array to file components. The file itself is not returned, only a downloadable link to the file in RAM.

## License

[MIT License](https://joshuaptfan.mit-license.org/)
