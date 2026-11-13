# Chat template fixtures

Copied unchanged from catena-models revision
`4bb7fdd`, `tests/fixtures/qwen3_chat.jinja` and
`tests/fixtures/qwen35_chat.jinja`. They exercise the same MiniJinja features as
the reference server. Production rendering always reads `tokenizer.chat_template`
from the caller's GGUF.

The small client packaging GGUF embeds `qwen3_chat.jinja`; regenerate it with
`python3 crates/client/src/model/package/make_mini_gguf.py` from the repository root.
