// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IDE_COMMANDS_H
#define IDE_COMMANDS_H

#include "cmd_interface_ide_responder.h"


int ide_km_query (const struct ide_driver *ide_driver, struct cmd_interface_msg *request);

int ide_km_key_prog (const struct ide_driver *ide_driver, struct cmd_interface_msg *request);

int ide_km_key_set_go (const struct ide_driver *ide_driver, struct cmd_interface_msg *request);

int ide_km_key_set_stop (const struct ide_driver *ide_driver, struct cmd_interface_msg *request);


#endif	/* IDE_COMMANDS_H */
