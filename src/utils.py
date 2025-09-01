from context import Context
import subprocess

ctx = Context()
info = ctx.logger.info
warn = ctx.logger.warn
error = ctx.logger.error
important = ctx.logger.important


def runcmd(*args: str, fail_on_error=False, verbose=True):
    try:
        p = subprocess.run(args, capture_output=True)
    except subprocess.CalledProcessError as e:
        error(f"subprocess error: {e}")
    stdout, stderr = p.stdout, p.stderr
    if stderr and verbose:
        try:
            stderr = stderr.decode("utf-8")
        except UnicodeDecodeError:
            pass
        if fail_on_error:
            error(stderr)
        else:
            warn(stderr)
    try:
        return stdout.decode("utf-8")
    except UnicodeDecodeError:
        pass
    return stdout
