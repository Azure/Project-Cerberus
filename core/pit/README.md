
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

/*
  Developed by AMI Inc. & Colorado State University.
  Contact person: Rakesh Podder. Email: rakeshpodder3@gmail.com
*/
PIT-Cerberus Framework

## This readme will contain information about the protection in transit features added.

pit_crypto.h/.c: Contains all the encryption, decrtption, keygeneration, OTP Generation and Validation functions.
pit.h/.c: Contains locking and unlocking functions.
pit_client.h/.c: Contains C-socket to connect with server.
pit-server.py: A server to communicate. 

How to run with the server:

1. Run the server first, it will wait for client to connect.
2. Build the Project-Cerberus as define in main readme.