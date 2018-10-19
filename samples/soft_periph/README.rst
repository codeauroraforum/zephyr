.. _soft_periph:

SW Defined Peripherals Sample
#############################

Overview
********
This example shows offloading of the real-time task from Linux using Zephyr and
RPMsg. It has been tested on the UDOO Neo board with NXP i.MX 6SoloX
heterogenous multicore SoC.

The Cortex-A9 core runs Linux and the Cortex-M4 core runs Zephyr for
the execution of a real-time task, which is emulation of the UART protocol using
GPIO pins. Communication between the two systems is done via RPMsg,
which internally uses Messaging Unit and shared memory on this platform.

Linux part consists of a kernel module, which creates virtual devices
/dev/ttySoftX to read and write data to the M4 core.

Zephyr part waits for the configuration message from Linux on an RPMsg endpoint.
Then it configures the emulation of UART using GPIO pins. It starts two
cooperative threads - to transmit and to receive data. The transmit thread reads
data received from Linux, decodes it into the form of UART pin changes which are
enqueued to a buffer. The buffer is consumed from a timer callback, which
toggles respective GPIO output pin(s). Timer callback also reads the input GPIO
pin(s) states and place them into the receive buffer. This is read by the
receive thread, which decodes it into bytes and sends it to the Linux using
RPMsg.

Building and Running the Zephyr Code
************************************

The project can be built and executed on UDOO Neo board as follows:

.. zephyr-app-commands::
   :zephyr-app: samples/soft_periph
   :host-os: unix
   :board: udoo_neo_full
   :goals: run
   :compact:

Follow the instructions in the :ref:`udoo_neo_full_m4` board documentation
for how to load the Zephyr binary to the desired core and execute it.

Building and Running the Linux Code
***********************************

The remote code and the instructions how to build and run it are located at:

https://source.codeaurora.org/external/imxsupport/lkm-softperipherals/

Sample Output
=============

.. code-block:: console

    SW UART demo is starting...
    waiting for peripherals configuration... 
