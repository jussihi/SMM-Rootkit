FROM ubuntu:16.04
MAINTAINER Jussi Hietanen

RUN \
	apt-get update && \
	apt-get -y install ccache build-essential python python-pip qemu sudo nano libgcc-5-dev uuid-dev nasm iasl git wget zip xorg-dev p7zip-full
