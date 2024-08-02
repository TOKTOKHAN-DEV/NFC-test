import usb1

context = usb1.USBContext()
for device in context.getDeviceList(skip_on_error=True):
    if device.getVendorID() == 0x072f and device.getProductID() == 0x2200:
        print(f'Found device: {device}')
        try:
            handle = device.open()
            print("Device opened successfully")
        except usb1.USBError as e:
            print(f"Could not open device: {e}")
