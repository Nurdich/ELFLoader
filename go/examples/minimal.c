// Minimal test with no external dependencies
int go(unsigned char* args, int len) {
    // Just do some simple calculations and return
    int result = 0;

    if (args != 0 && len > 0) {
        for (int i = 0; i < len; i++) {
            result += args[i];
        }
    }

    return result + 42;
}
