import math

# data from https://people.sc.fsu.edu/~jburkardt/datasets/ngrams/english_quadgrams.txt
data = """
"""

lines = [line.strip() for line in data.strip().splitlines()]
ngrams = []
total = sum(int(line.split()[1]) for line in lines)

for line in lines:
    ngram, count = line.split()
    count = int(count)
    log_prob = math.log(count / total)
    ngrams.append(f'("{ngram}",{log_prob:.4f})')

print(",".join(ngrams))