Introduction
============

.. image:: https://readthedocs.org/projects/circuitpython-hmac/badge/?version=latest
    :target: https://circuitpython.readthedocs.io/projects/hmac/en/latest/
    :alt: Documentation Status

.. image:: https://img.shields.io/discord/327254708534116352.svg
    :target: https://adafru.it/discord
    :alt: Discord

.. image:: https://github.com/jimbobbennett/CircuitPython_HMAC/workflows/Build%20CI/badge.svg
    :target: https://github.com/jimbobbennett/CircuitPython_HMAC/actions
    :alt: Build Status

.. image:: https://img.shields.io/badge/code%20style-black-000000.svg
    :target: https://github.com/psf/black
    :alt: Code Style: Black

HMAC (Keyed-Hashing for Message Authentication) Python module. Implements the HMAC algorithm as described by RFC 2104.


Dependencies
=============
This driver depends on:

* `Adafruit CircuitPython <https://github.com/adafruit/circuitpython>`_
* `Adafruit CircuitPython Hashlib <https://github.com/adafruit/Adafruit_CircuitPython_hashlib>`_

Please ensure all dependencies are available on the CircuitPython filesystem.
This is easily achieved by downloading
`the Adafruit library and driver bundle <https://circuitpython.org/libraries>`_.

Installing from PyPI
=====================

On supported GNU/Linux systems like the Raspberry Pi, you can install the driver locally `from
PyPI <https://pypi.org/project/circuitpython-hmac/>`_. To install for current user:

.. code-block:: shell

    pip3 install circuitpython-hmac

To install system-wide (this may be required in some cases):

.. code-block:: shell

    sudo pip3 install circuitpython-hmac

To install in a virtual environment in your current project:

.. code-block:: shell

    mkdir project-name && cd project-name
    python3 -m venv .env
    source .env/bin/activate
    pip3 install circuitpython-hmac

Usage Example
=============

Create a keyed hash for authenticating a message.

.. code-block:: python

    secret = "secret"
    msg = "message"

    key = hmac.new(secret, msg=msg, digestmod=hashlib.sha256).digest()

Contributing
============

Contributions are welcome! Please read our `Code of Conduct
<https://github.com/jimbobbennett/CircuitPython_HMAC/blob/master/CODE_OF_CONDUCT.md>`_
before contributing to help this project stay welcoming.

Documentation
=============

For information on building library documentation, please check out `this guide <https://learn.adafruit.com/creating-and-sharing-a-circuitpython-library/sharing-our-docs-on-readthedocs#sphinx-5-1>`_.
