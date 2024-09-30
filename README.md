# IP Traceroute

This project implements an IP traceroute tool in C, providing detailed information about each hop in the route to a specified destination.

## Features

- Traces the route to a given host
- Displays IP addresses of intermediate hops
- Shows round-trip time for each hop
- Performs reverse DNS lookup
- Retrieves geolocation and ISP information for each hop
- Visualizes the route progress

## Requirements

- GCC compiler
- libcurl library
- Root privileges (for creating raw sockets)

## Dependencies

This project requires the following libraries:
- stdio.h
- stdlib.h
- string.h
- unistd.h
- arpa/inet.h
- sys/socket.h
- netinet/in.h
- netinet/ip.h
- netinet/ip_icmp.h
- netdb.h
- curl/curl.h
- sys/time.h

## Compilation

To compile the program, use the following command:

```
gcc -o traceroute main.c -lcurl
```

## Usage

Run the compiled program with root privileges:

```
sudo ./traceroute
```

When prompted, enter the website address or IP you want to trace.

## Output

The program will display:
- Hop number
- IP address of each hop
- Round-trip time
- Hostname (if available)
- Geolocation information (country, region, city)
- ISP information
- AS (Autonomous System) information
- A visual representation of the route progress
