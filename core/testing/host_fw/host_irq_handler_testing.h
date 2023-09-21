// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_IRQ_HANDLER_TESTING_H_
#define HOST_IRQ_HANDLER_TESTING_H_

#include "testing.h"
#include "host_fw/host_irq_handler.h"
#include "testing/mock/host_fw/bmc_recovery_mock.h"
#include "testing/mock/host_fw/host_irq_control_mock.h"
#include "testing/mock/host_fw/host_processor_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"


/**
 * Dependencies for testing.
 */
struct host_irq_handler_testing {
	HASH_TESTING_ENGINE hash;				/**< Hash engine to use for reset validation. */
	RSA_TESTING_ENGINE rsa;					/**< RSA engine to use for reset validation. */
	struct host_processor_mock host;		/**< Mock for host processor. */
	struct bmc_recovery_mock recovery;		/**< Mock for BMC watchdog boot recovery. */
	struct host_irq_control_mock irq;		/**< Mock for host IRQ controller. */
	struct host_irq_handler test;			/**< Host interrupt handler under test. */
	struct logging_mock logger;				/**< Mock for debug logging. */
};


void host_irq_handler_testing_init_dependencies (CuTest *test,
	struct host_irq_handler_testing *host);

void host_irq_handler_testing_release_dependencies (CuTest *test,
	struct host_irq_handler_testing *host);



#endif /* HOST_IRQ_HANDLER_TESTING_H_ */
