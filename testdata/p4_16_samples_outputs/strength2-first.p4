control strength() {
    apply {
        bit<4> x;
        bit<4> y;
        bit<4> z;
        z = x ^ y;
        if (x < y) {
            ;
        } else {
            z = x ^ (y | z);
        }
        if (x > y) {
            ;
        } else {
            z = x ^ y & z;
        }
    }
}

