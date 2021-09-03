#ifndef INTRUSION_MANAGER_ASYNC_H_
#define INTRUSION_MANAGER_ASYNC_H_

#include "intrusion/intrusion_manager.h"
#include "intrusion/intrusion_state_observer.h"


/**
 * An intrusion manager that supports asynchronous notification of intrusion state.
 */
struct intrusion_manager_async {
	struct intrusion_manager base;					/**< Base manager instance. */
	struct intrusion_state_observer base_observer;	/**< Base instance for state notifications. */
};


int intrusion_manager_async_init (struct intrusion_manager_async *manager,
	struct intrusion_state *state, struct hash_engine *hash, struct pcr_store *pcr,
	uint16_t measurement);
void intrusion_manager_async_release (struct intrusion_manager_async *manager);


#endif /* INTRUSION_MANAGER_ASYNC_H_ */
