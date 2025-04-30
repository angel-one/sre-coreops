# coreops/logging_utils.py

import logging
import sys

def setup_logger(name: str = "coreops"):
    """
    Sets up a logger with a specified name, logging level, and output format.

    Args:
        name (str): The name of the logger. Defaults to 'coreops'.

    Returns:
        logging.Logger: A configured logger instance.
    """
    # Create or retrieve a logger with the specified name
    logger = logging.getLogger(name)
    # Set the logging level to INFO
    logger.setLevel(logging.INFO)

    # Create a stream handler to output logs to stdout
    handler = logging.StreamHandler(sys.stdout)
    # Define the log message format
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    # Set the formatter for the handler
    handler.setFormatter(formatter)

    # Add the handler to the logger if it doesn't already have handlers
    if not logger.handlers:
        logger.addHandler(handler)

    return logger