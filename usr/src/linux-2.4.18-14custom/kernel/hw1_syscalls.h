#include <linux/sched.h>
#include <linux/slab.h>
#include <asm/uaccess.h>

#define PASS 234123

void move_elements(task_t* found_task,int size);
int sys_enable_policy (pid_t pid ,int size, int password);
int sys_disable_policy (pid_t pid ,int password);
int sys_set_process_capabilities(pid_t pid,int new_level,int password);
int sys_get_process_log(pid_t pid,int size,struct forbidden_activity_info* user_mem);

int sys_enable_policy (pid_t pid ,int size, int password) {
    if(pid<0){
        return -ESRCH;
    }
    task_t* found_task=find_task_by_pid(pid);
    if(!found_task){
        return -ESRCH;
    }
	
	if(password != PASS || found_task->policy_enabled || size<0) {
		return -EINVAL;
	}

    found_task->forbidden_queue=kmalloc(sizeof(*found_task->forbidden_queue)*size,GFP_KERNEL);
    if(!found_task->forbidden_queue){
        return -ENOMEM;
    }

    found_task->policy_enabled=1;
	found_task->policy_current_level = 2;
    found_task->forbidden_max_size=size;
    found_task->forbidden_next_index=0;
    return 0;
}

int sys_disable_policy (pid_t pid ,int password) {
    if(pid<0){
        return -ESRCH;
    }
    task_t* found_task=find_task_by_pid(pid);
    if(!found_task){
        return -ESRCH;
    }
    if(!found_task->policy_enabled || password != PASS){
        return -EINVAL;
    }
    found_task->policy_enabled=0;
    kfree(found_task->forbidden_queue);
    found_task->forbidden_queue=NULL; //overkill- should never access forbidden queue when it is not enabled
    found_task->forbidden_max_size=0;
    found_task->forbidden_next_index=0;

    return 0;
}

int sys_set_process_capabilities(pid_t pid,int new_level,int password) {
	if(pid<0) {
		return -ESRCH;
	}
	
	task_t* found_task = find_task_by_pid(pid);
	if(!found_task){
        return -ESRCH;
    }

	if(new_level>2 || new_level<0 || password != PASS || !found_task->policy_enabled) {
		return -EINVAL;
	}
	
	/* NOT CLEAR: what kind of memory isssue can occur here? */
	
	found_task->policy_current_level=new_level;
	
	return 0;
}


int sys_get_process_log(pid_t pid,int size,struct forbidden_activity_info* user_mem) {
    if(pid<0){
        return -ESRCH;
    }
    task_t* found_task=find_task_by_pid(pid);
    if(!found_task){
        return -ESRCH;
    }
    if( size > found_task->forbidden_next_index || size < 0 || !found_task->policy_enabled || !user_mem){
        return -EINVAL;
    }
    if(size==0){ //nothing to do here
        return 0;
    }
    if(copy_to_user(user_mem, found_task->forbidden_queue, size * sizeof(*found_task->forbidden_queue) )){ //return 0 on sucess
        return -ENOMEM;
    }

    //here should be the logic of cyclic array
    move_elements(found_task,size);
   
    return 0;
}

struct forbidden_activity_info make_forbid(int syscall_req_level,int proc_level,int time) {
	struct forbidden_activity_info f;
	f.syscall_req_level = syscall_req_level;
	f.proc_level=proc_level;
	f.time = time;
	return f;
}

void add_to_queue(task_t* task, struct forbidden_activity_info new_activity) {
	if(task->forbidden_max_size == task->forbidden_next_index) {
		return;
	}
	task->forbidden_queue[(task->forbidden_next_index)++] = new_activity;
}

void move_elements(task_t* found_task,int size){
      int i;
      int remainingElements= found_task->forbidden_next_index - size;
      for(i=0;i<remainingElements;i++){
          found_task->forbidden_queue[i]=found_task->forbidden_queue[i+size];
      }
      found_task->forbidden_next_index-=size;
}