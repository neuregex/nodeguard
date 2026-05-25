"""Trivial benign node: adds two numbers."""


class SimpleAddNode:
    """A ComfyUI-style node that adds two integers."""

    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "a": ("INT", {"default": 0}),
                "b": ("INT", {"default": 0}),
            }
        }

    RETURN_TYPES = ("INT",)
    FUNCTION = "add"
    CATEGORY = "math"

    def add(self, a: int, b: int) -> tuple[int]:
        return (a + b,)
