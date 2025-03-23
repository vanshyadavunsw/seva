#include <stdlib.h>
#include "fsm.h"

typedef bool (*predicate_func)(void *context);
typedef int (*action_func)(void *context, bool *transition);

struct handler {
    predicate_func predicate;
    action_func action;
};

struct state_machine {
    int state;
    void *context;
    Handler **handlers;
};

void run_fsm(StateMachine *fsm) {
    while (fsm->state != TERMINATION_STATE) {
        Handler *handler_list = fsm->handlers[fsm->state];
        Handler current;

        int i = 0;

        while (true) {
            current = handler_list[i];

            if (current.action == nullptr) {
               break;
            }

            if (current.predicate(fsm->context)) {
                bool transition;
                int next_state = current.action(fsm->context, &transition);

                if (transition) {
                    fsm->state = next_state;
                    break;
                }
            }

            i++;
        }
    }
}
