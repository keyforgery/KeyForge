FROM ubuntu:latest

ENV DEBIAN_FRONTEND noninteractive
ENV INITRD No
ENV LANG en_US.UTF-8


RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      vim wget curl sudo net-tools pwgen \
      zsh postfix mailutils tree libsasl2-modules \
      git-core logrotate software-properties-common \
      cmake git build-essential libgmp-dev \ 
      openssl python3-setuptools python3-pip libmilter-dev \
      libmilter1.0.1 && \
    add-apt-repository -y ppa:longsleep/golang-backports && \
    apt-get update && \
    apt-get install -y --no-install-recommends golang-go && \
    apt-get clean 
    # && \
    #rm -rf /var/lib/apt/lists/*


WORKDIR /root

RUN git clone https://github.com/relic-toolkit/relic.git

WORKDIR /root/relic/

#RUN git checkout b984e901 # Confirmed working
#RUN git checkout d98b7bda093468abadababdc9c72c5415a6257b6 # works
#RUN git checkout d793965b43798b85158165262c3a8b8233545a39   
#RUN git checkout 5e9d12ed8b9b8d6c587c7bf450c9fcc5b9735965  #FAILS
#RUN git checkout 3ecad63f5b986ee293b271598bcc2c20a24e0101 
#RUN git checkout cb266746e410b4c00b3439f293194334a57b79aa

RUN mkdir /root/relic/relic-target
WORKDIR /root/relic/relic-target

RUN cmake ../ -DALLOC=DYNAMIC -DFP_PRIME=381 -DARITH=gmp-sec  \
              -DWSIZE=64 -DFP_METHD="INTEG;INTEG;INTEG;MONTY;LOWER;SLIDE" \
              -DCOMP="-O3 -mtune=native -march=native" -DFP_PMERS=off -DFP_QNRES=on \
              -DFPX_METHD="INTEG;INTEG;LAZYR" -DEP_SUPER=off -DPP_METHD="LAZYR;OATEP" \
              && make && make install

# install ohmyzsh for sanity reasons 
RUN wget https://github.com/robbyrussell/oh-my-zsh/raw/master/tools/install.sh -O - | zsh || true

RUN mkdir -p "/root/go/src/github.com/keyforgery/KeyForge/"

# Set up the correct paths
WORKDIR /root/go/src/github.com/keyforgery/KeyForge

# Copy everything to the remote directory
copy .  /root/go/src/github.com/keyforgery/KeyForge

RUN echo "GOPATH=/root/go\n" >> /root/.zshrc
RUN echo "LD_LIBRARY_PATH=/usr/local/lib" >> /root/.zshrc
RUN echo "PATH=$PATH:/root/go/bin" >> /root/.zshrc

RUN go get golang.org/x/crypto/sha3

# Install the remote libs
RUN ldconfig

# Run benchmakrs
# Install the golang equivalent
WORKDIR /root/go/src/github.com/keyforgery/KeyForge/
RUN go install ./...

WORKDIR /root/go/src/github.com/keyforgery/KeyForge/crypto/hibs
RUN go test -bench=. -count 3


# ZSH as our command shell
CMD ["zsh"]

