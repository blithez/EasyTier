# Base image. Defaults to the CI registry image, but can be overridden to build
# from any image already available locally (no registry access needed), e.g.:
#   docker build --build-arg BASE_IMAGE=debian:12 docker/
FROM docker.io/library/ubuntu:resolute

# USER and GROUP are reserved keywords in Dockerfile syntax, so
# put a MY_ prefix in front of these things.
ARG MY_USER
ARG MY_GROUP
ARG MY_UID
ARG MY_GID

ENV DEBIAN_FRONTEND noninteractive
ENV RUSTUP_DIST_SERVER="https://mirrors.ustc.edu.cn/rust-static" \
    RUSTUP_UPDATE_ROOT="https://mirrors.ustc.edu.cn/rust-static/rustup"

# Use mirror, skip sources
RUN sed -i \
    -e "s|//.*\.ubuntu\.com/ubuntu|//mirrors.ustc.edu.cn/ubuntu|" \
    /etc/apt/sources.list.d/ubuntu.sources

# Disable Ubuntu Extended Security Maintenance (Jenkins can't fetch these)
# RUN rm /etc/apt/sources.list.d/ubuntu-esm-infra-trusty.list

# Add i386 for wine
# RUN dpkg --add-architecture i386

# GTS: This package is needed by neither minerva nor pinenut
## Add crafmsprogs for bionic, if not installed,
## Note: it's not available in bionic's apt packages
#RUN if [ $(dpkg-query -W -f='${Status}' cramfsprogs 2>/dev/null | grep -c "ok installed") -eq 0 ];                                            \
#    then                                                                                                                                      \
#        apt-get update && apt-get -y install wget && \
#        cd /tmp && wget http://archive.ubuntu.com/ubuntu/pool/universe/c/cramfs/cramfsprogs_1.1-6ubuntu1_amd64.deb && dpkg -i cramfsprogs_1.1-6ubuntu1_amd64.deb; \
#    fi

# NOTE: win-iconv-mingw-w64-dev was removed: it only exists in Ubuntu (universe),
# never in Debian, so apt fails with "Unable to locate package". It is not needed:
# armgcc_build.sh builds its own static libiconv for the mingw host and passes it
# via --with-iconv=$ICONV_LIB_PATH.
RUN apt-get update \
    && apt-get -y install \
    sudo \
    systemd \
    adduser \
    wget \
    protobuf-compiler \
    libclang-dev \
    libprotobuf-dev \
    gcc \
    gcc-arm-linux-gnueabihf \
    rustup \
    && rm -rf /var/lib/apt/lists

RUN rustup default 1.95 && rustup target add armv7-unknown-linux-gnueabihf

RUN userdel -r ubuntu && groupdel ubuntu || true

# Set up user for whoami (and others)
RUN addgroup --gid $MY_GID $MY_GROUP && \
    adduser --uid $MY_UID --gid $MY_GID --home /home/$MY_USER --shell /bin/sh \
    --disabled-password --gecos "" $MY_USER && \
    usermod -aG sudo $MY_USER && \
    echo "$MY_USER ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
