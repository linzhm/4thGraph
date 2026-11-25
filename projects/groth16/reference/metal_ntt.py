"""BLS12-381 scalar-field transforms using wgpu-py and the gnark WGSL kernel."""

from hashlib import sha256
from struct import pack

import wgpu

from field import R


SHADER_SHA256 = "923fbba9e75ec5c6c6a921e655db79ffa1520c85e1c33c6109155a95b3d472a6"
FIELD_BYTES = 32
RADIX = (1 << 256) % R
RADIX_INV = pow(RADIX, -1, R)
WORKGROUP_SIZE = 256
TILE_SIZE = 2 * WORKGROUP_SIZE
STAGES_PER_PASS = TILE_SIZE.bit_length() - 1
REVERSE_INPUT, SCALE_OUTPUT, INVERSE = 1, 4, 8
STORAGE = wgpu.BufferUsage.STORAGE | wgpu.BufferUsage.COPY_SRC | wgpu.BufferUsage.COPY_DST


def powers(base, count):
    result = [1]
    for _ in range(count - 1):
        result.append(result[-1] * base % R)
    return result


def _montgomery(values):
    return b"".join((value * RADIX % R).to_bytes(FIELD_BYTES, "little") for value in values)


class MetalNtt:
    """Hold a Metal device, transform pipeline and the current domain's twiddles."""

    def __init__(self, shader_path):
        adapter = wgpu.gpu.request_adapter_sync(power_preference="high-performance")
        if adapter.info["backend_type"] != "Metal" or adapter.info["adapter_type"] == "CPU":
            raise RuntimeError("the Python prover requires a hardware Metal adapter")
        limits = ("max-buffer-size", "max-storage-buffer-binding-size")
        self.device = adapter.request_device_sync(required_limits={key: adapter.limits[key] for key in limits})
        self.adapter = dict(adapter.info)
        self.pipeline = self._pipeline(shader_path, SHADER_SHA256, "fr_ntt_fused_main")
        self.domain = None
        self.twiddles = None

    def _pipeline(self, path, expected, entry):
        source = path.read_bytes()
        if sha256(source).hexdigest() != expected:
            raise ValueError(f"unexpected BLS12-381 {path.name} fingerprint")
        module = self.device.create_shader_module(code=source.decode("utf-8"))
        return self.device.create_compute_pipeline(
            layout="auto", compute={"module": module, "entry_point": entry},
        )

    def _dispatch(self, compute, pipeline, buffers, params, columns, rows=1):
        uniform = self.device.create_buffer_with_data(data=params, usage=wgpu.BufferUsage.UNIFORM)
        bindings = self.device.create_bind_group(layout=pipeline.get_bind_group_layout(0), entries=[
            {"binding": i, "resource": {"buffer": buffer, "offset": 0, "size": buffer.size}}
            for i, buffer in enumerate((*buffers, uniform))
        ])
        compute.set_pipeline(pipeline)
        compute.set_bind_group(0, bindings)
        compute.dispatch_workgroups(columns, rows)

    def _record_ntt(self, compute, active, other, twiddles, count, *, inverse=False):
        if count == 1:
            return active, other
        log_n = count.bit_length() - 1
        groups = (count + TILE_SIZE - 1) // TILE_SIZE
        columns = min(groups, self.device.limits["max-compute-workgroups-per-dimension"])
        rows = (groups + columns - 1) // columns
        for first_stage in range(0, log_n, STAGES_PER_PASS):
            stage_count = min(STAGES_PER_PASS, log_n - first_stage)
            flags = INVERSE if inverse else 0
            load = store = bytes(FIELD_BYTES)
            if first_stage == 0:
                flags |= REVERSE_INPUT
            if inverse and first_stage + stage_count == log_n:
                flags |= SCALE_OUTPUT
                store = _montgomery([pow(count, -1, R)])
            params = pack("<8I", count, first_stage, stage_count, flags, log_n, 0, 0, 0) + load + store
            self._dispatch(compute, self.pipeline, (active, twiddles, other), params, columns, rows)
            active, other = other, active
        return active, other

    def _check_size(self, byte_size):
        if byte_size > self.device.limits["max-storage-buffer-binding-size"]:
            raise ValueError(f"the {byte_size}-byte vector exceeds the Metal storage buffer limit")

    def transform(self, values, root, *, inverse=False):
        count = len(values)
        if count == 1:
            return list(values)
        byte_size = FIELD_BYTES * count
        self._check_size(byte_size)
        domain = (count, root)
        if self.domain != domain:
            twiddles = _montgomery(powers(root, count // 2))
            self.twiddles = self.device.create_buffer_with_data(data=twiddles, usage=wgpu.BufferUsage.STORAGE)
            self.domain = domain
        device = self.device
        active = device.create_buffer_with_data(data=_montgomery(values), usage=STORAGE)
        other = device.create_buffer(size=byte_size, usage=STORAGE)
        command = device.create_command_encoder()
        compute = command.begin_compute_pass()
        active, _ = self._record_ntt(compute, active, other, self.twiddles, count, inverse=inverse)
        compute.end()
        device.queue.submit([command.finish()])
        packed = device.queue.read_buffer(active)
        return [int.from_bytes(packed[i:i + FIELD_BYTES], "little") * RADIX_INV % R
                for i in range(0, byte_size, FIELD_BYTES)]
