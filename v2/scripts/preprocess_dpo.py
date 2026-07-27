import json
import sys

src = sys.argv[1]
dst = sys.argv[2]

count = 0
with open(src) as f_in, open(dst, "w") as f_out:
    for line in f_in:
        d = json.loads(line)
        chosen_msgs = d["chosen"]
        rejected_msgs = d["rejected"]
        
        sys_msg = ""
        user_msg = ""
        for m in chosen_msgs:
            if m["role"] == "system":
                sys_msg = m["content"]
            elif m["role"] == "user":
                user_msg = m["content"]
        
        prompt = f"<|im_start|>system\n{sys_msg}<|im_end|>\n<|im_start|>user\n{user_msg}<|im_end|>\n<|im_start|>assistant\n"
        
        chosen_resp = chosen_msgs[-1]["content"] if chosen_msgs[-1]["role"] == "assistant" else ""
        rejected_resp = rejected_msgs[-1]["content"] if rejected_msgs[-1]["role"] == "assistant" else ""
        
        out = {"prompt": prompt, "chosen": chosen_resp, "rejected": rejected_resp}
        f_out.write(json.dumps(out) + "\n")
        count += 1

print(f"Processed {count} DPO samples")
