#ifndef FSM_H
#define FSM_H

#define TERMINATION_STATE 0

typedef struct state_machine StateMachine;
typedef struct handler Handler;

void run_fsm(StateMachine *fsm);

#endif
