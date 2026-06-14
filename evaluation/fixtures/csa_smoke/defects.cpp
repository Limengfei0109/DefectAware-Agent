int null_dereference() {
    int* pointer = nullptr;
    return *pointer;
}

int divide_by_zero() {
    int denominator = 0;
    return 42 / denominator;
}

int safe_null_check(int* pointer) {
    if (!pointer) {
        return 0;
    }
    return *pointer;
}
