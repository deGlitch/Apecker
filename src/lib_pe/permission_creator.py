class PermissionsCreator:

    @staticmethod
    def create(read = True, write = True, execute = True):
        value = 0
        if execute:
            value |= 0x20000000
        if read:
            value |= 0x40000000
        if write:
            value |= 0x80000000
        return value