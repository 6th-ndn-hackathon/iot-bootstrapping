# iot-bootstrapping

Project Leads: Yanbiao Li, Zhiyi Zhang, Haitao Zhang

Motivation and Problem Statement

Enroll a new IoT device in your home network, such that it can securely communicate with all other devices in the same network with NDN

Contribution to NDN

The first step to NDNoT; May also be used in security setup of NDN Edges

Tasks

Implement a Controller on android phone: scan QR code; distribute TrustAnchor; issue Certificate
Implement a Device on Raspberry Pi; initialize bootstrapping; generate key-pair and install Cert
Required Knowledge for Participants

C/C++
ndn-cxx
NFD-android
jNDN
DH key exchange
public-key encryption/decryption
Expected Outcomes

The implementation of Controller and Device
Use the Phone to bootstrap the device; then the device is able to communicate with the laptop
slide deck for design details: https://www.dropbox.com/s/6vxk13cho3isqdp/IoT%20security%20bootstrapping.pptx?dl=0
