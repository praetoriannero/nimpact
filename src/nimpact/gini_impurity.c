#include <math.h>

float giniImpurityImpl(unsigned char* byte, unsigned int size) {
    unsigned int i = 0;
    unsigned int ones = 0;
    float result;
    float ones_prob;
    for(i = 0; i < size; i += 1){
        ones += __builtin_popcount(*byte);
        byte += sizeof(char);
    }

    ones_prob = (float)ones / ((float)size * 8);
    result = 1 - ((ones_prob * ones_prob) + ((1 - ones_prob) * (1 - ones_prob)));
    return result;
}
