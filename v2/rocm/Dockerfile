# RakshakAI v2 — ROCm 6.2 + PyTorch + Axolotl
# Single MI300X (192 GB) target. ~25 GB image.

FROM rocm/dev-ubuntu-22.04:6.2.4

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HF_HOME=/workspace/rakshakai/v2/inputs/hf_home \
    TRANSFORMERS_CACHE=/workspace/rakshakai/v2/inputs/hf_cache \
    TOKENIZERS_PARALLELISM=false \
    BNB_CUDA_VERSION=130 \
    PYTORCH_ROCM_ALLOC_CONF=expandable_segments:True

RUN apt-get update && apt-get install -y --no-install-recommends \
        git git-lfs curl wget ca-certificates build-essential ninja-build \
        libssl-dev libffi-dev libbz2-dev liblzma-dev libsqlite3-dev \
        libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev \
        libedit-dev libreadline-dev zlib1g-dev libpng-dev \
        tmux htop nvtop pciutils \
    && rm -rf /var/lib/apt/lists/* \
    && git lfs install --system

# Miniconda for clean python env
RUN wget -qO /tmp/miniconda.sh https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh \
    && bash /tmp/miniconda.sh -b -p /opt/conda \
    && rm /tmp/miniconda.sh
ENV PATH=/opt/conda/bin:$PATH

RUN conda create -n rakshak python=3.11 -y && conda clean -afy
SHELL ["bash", "-lc"]
RUN echo "conda activate rakshak" >> /root/.bashrc

# PyTorch ROCm 6.2
RUN /opt/conda/envs/rakshak/bin/pip install --no-cache-dir \
        --index-url https://download.pytorch.org/whl/rocm6.2 \
        torch==2.4.1+rocm6.2 \
        torchvision==0.19.1+rocm6.2 \
        torchaudio==2.4.1+rocm6.2

# bitsandbytes (must match PyTorch ABI)
RUN /opt/conda/envs/rakshak/bin/pip install --no-cache-dir \
        bitsandbytes==0.43.3

# Flash-Attn 2 (ROCm build)
ENV FLASH_ATTENTION_FORCE_BUILD=TRUE
RUN /opt/conda/envs/rakshak/bin/pip install --no-cache-dir flash-attn==2.5.9.post1 --no-build-isolation

# Training & serving stack
RUN /opt/conda/envs/rakshak/bin/pip install --no-cache-dir \
        "transformers>=4.43,<5" \
        "peft>=0.11" \
        "accelerate>=0.33" \
        "trl>=0.9.6" \
        "datasets>=2.20" \
        "deepspeed>=0.14" \
        "vllm>=0.5.3" \
        "autoawq>=0.2.5" \
        "axolotl==0.7.0" \
        "wandb>=0.17" \
        "scikit-learn>=1.5" \
        "pandas>=2.2" \
        "pyarrow>=16" \
        "fastapi>=0.111" \
        "uvicorn[standard]>=0.30" \
        "pydantic>=2.7" \
        "tree-sitter==0.21" \
        "tree-sitter-languages" \
        "langdetect>=1.0.9" \
        "tiktoken>=0.7" \
        "matplotlib>=3.8" \
        "seaborn>=0.13"

WORKDIR /workspace/rakshakai
COPY env.sh /workspace/rakshakai/v2/rocm/env.sh
RUN echo "source /workspace/rakshakai/v2/rocm/env.sh" >> /root/.bashrc

# Pre-download the base model at build time for offline training
# (comment out if you prefer to download at first run)
# RUN /opt/conda/envs/rakshak/bin/python -c "from huggingface_hub import snapshot_download; \
#       snapshot_download('Qwen/Qwen2.5-Coder-7B-Instruct', cache_dir='/workspace/rakshakai/v2/inputs/hf_cache')"

CMD ["/bin/bash"]
