import random

def generate_permutation():
    # Define the input and output sets
    input_set = list("abcdefghijklmnopqrstuvwxyz \n")
    output_set = list("abcdefghijklmnopqrstuvwxyz01")

    # Ensure the output set has the same length as the input set
    if len(input_set) != len(output_set):
        raise ValueError("Input and output sets must have the same length")

    # Shuffle the output set to create a random permutation
    random.shuffle(output_set)

    # Create a mapping from input to output
    permutation = dict(zip(input_set, output_set))

    return permutation

if __name__ == "__main__":
    permutation = generate_permutation()
    print (permutation)