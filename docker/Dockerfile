################################################################################
# SPYPHONE INVESTIGATION - DOCKER CONTAINER
################################################################################
#
# PURPOSE:
#   Provides a complete, portable environment for mobile surveillance detection.
#   Everything pre-configured: ADB, Frida, Python tools, network analyzers.
#
# WHY USE DOCKER:
#   - Consistent environment (same tools, same versions)
#   - No conflicts with host system
#   - Easy to share and reproduce
#   - Works on macOS, Linux, Windows (with Docker)
#
# WHAT'S INCLUDED:
#   - Android tools (ADB, fastboot)
#   - Frida and frida-tools
#   - Python 3 with all analysis libraries
#   - Network analysis tools (tcpdump, tshark)
#   - All investigation scripts
#
# HOW TO BUILD:
#   docker build -t spyphone-analyzer -f docker/Dockerfile .
#
# HOW TO RUN:
#   docker run -it --privileged \
#     -v /dev/bus/usb:/dev/bus/usb \
#     -v $(pwd)/data:/workspace/data \
#     spyphone-analyzer
#
# NOTE:
#   --privileged and USB mounting required for ADB to access phone
#
# BASE IMAGE: Ubuntu 22.04 LTS (stable, well-supported)
################################################################################

FROM ubuntu:22.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

################################################################################
# INSTALL SYSTEM DEPENDENCIES
################################################################################
# Install all required packages in one layer to minimize image size
RUN apt-get update && apt-get install -y \
    # -------------------------------------------------------------------------
    # Build Tools (for compiling Python packages with native extensions)
    # -------------------------------------------------------------------------
    build-essential \
    git \
    curl \
    wget \
    # -------------------------------------------------------------------------
    # Android Tools (communicate with device)
    # -------------------------------------------------------------------------
    android-tools-adb \        # Android Debug Bridge
    android-tools-fastboot \   # Bootloader communication (not used, but useful)
    # -------------------------------------------------------------------------
    # Network Analysis Tools (capture and analyze traffic)
    # -------------------------------------------------------------------------
    tcpdump \                  # Command-line packet capture
    wireshark-common \         # Wireshark libraries
    tshark \                   # Command-line Wireshark
    nmap \                     # Network mapper (for port scanning)
    # -------------------------------------------------------------------------
    # Python Environment (for analysis scripts)
    # -------------------------------------------------------------------------
    python3 \                  # Python 3 interpreter
    python3-pip \              # Package installer
    python3-dev \              # Development headers (for native extensions)
    # -------------------------------------------------------------------------
    # Terminal Utilities (for better user experience)
    # -------------------------------------------------------------------------
    vim \                      # Text editor
    nano \                     # Simpler text editor
    htop \                     # Process viewer
    screen \                   # Terminal multiplexer
    tmux \                     # Better terminal multiplexer
    # -------------------------------------------------------------------------
    # USB Support (required for ADB to see phone)
    # -------------------------------------------------------------------------
    libusb-1.0-0 \             # USB library
    usbutils \                 # USB utilities (lsusb, etc.)
    # -------------------------------------------------------------------------
    # Cleanup to reduce image size
    # -------------------------------------------------------------------------
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (for some Frida scripts)
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g npm@latest

# Create working directory
WORKDIR /workspace

# Copy requirements
COPY requirements.txt .

# Install Python packages
RUN pip3 install --no-cache-dir -r requirements.txt

# Install additional Frida components
RUN pip3 install --no-cache-dir frida-tools frida

# Copy project files
COPY scripts/ ./scripts/
COPY frida/ ./frida/

# Create data directories
RUN mkdir -p data/logs data/captures data/reports

# Set up ADB server
RUN adb start-server || true

# Configure USB access (will need --privileged flag when running)
RUN groupadd -f plugdev && \
    usermod -a -G plugdev root

# Default command
CMD ["/bin/bash"]

# Usage instructions
RUN echo '#!/bin/bash' > /workspace/help.sh && \
    echo 'echo "==================================="' >> /workspace/help.sh && \
    echo 'echo "SpyPhone Investigation Container"' >> /workspace/help.sh && \
    echo 'echo "==================================="' >> /workspace/help.sh && \
    echo 'echo ""' >> /workspace/help.sh && \
    echo 'echo "Available commands:"' >> /workspace/help.sh && \
    echo 'echo "  adb devices - Check connected devices"' >> /workspace/help.sh && \
    echo 'echo "  python3 scripts/monitor_baseline.py"' >> /workspace/help.sh && \
    echo 'echo "  python3 scripts/monitor_conversation.py --keywords \"test\""' >> /workspace/help.sh && \
    echo 'echo ""' >> /workspace/help.sh && \
    echo 'echo "Data directories:"' >> /workspace/help.sh && \
    echo 'echo "  /workspace/data/logs - Frida logs"' >> /workspace/help.sh && \
    echo 'echo "  /workspace/data/captures - Network captures"' >> /workspace/help.sh && \
    echo 'echo "  /workspace/data/reports - Analysis reports"' >> /workspace/help.sh && \
    echo 'echo ""' >> /workspace/help.sh && \
    chmod +x /workspace/help.sh

# Display help on container start
RUN echo './help.sh' >> /root/.bashrc

