Downloaded and extracted arduino_cli from github

https://github.com/arduino/arduino-cli/releases/download/0.25.1/arduino-cli_0.25.1_Linux_64bit.tar.gz

~/apps/arduino-cli core install arduino:avr

arduino-cli board list

~/apps/arduino-cli core install arduino:avr

~/apps/arduino-cli board attach -p /dev/ttyACM0 sao_badge

arduino_cli compile sao_badge

# Build and Run
~/apps/arduino-cli compile sao_badge && ~/apps/arduino-cli upload sao_badge
