#!/bin/zsh

python3 cadipStationMock.py "127.0.0.1" "5000"
pytest tests/cadipStationMockTest.py # capture output mayb
echo $?
