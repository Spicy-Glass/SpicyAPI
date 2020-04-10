import atexit

from .async_ import process_pool
from firebasemodified import *
import logging

@atexit.register
def close_process_pool():
    """
    Clean up function that closes and terminates the process pool
    defined in the ``async`` file.
    """
    logging.basicConfig(filename='program.log', level='INFO')
    try:
        process_pool.close()
        process_pool.join()
        process_pool.terminate()
    except Exception as E:
        logging.warning(str(E))
        logging.warning("Closing process failed")
