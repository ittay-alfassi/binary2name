import argparse
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-path', type= str)
    args=parser.parse_args()
    f = open(args.path, "r")
    m = 0
    for line in f:
        m=max(m,len(line.split(" ")[1].split(",")[1].split("|")))
        #context=line.split(" ")[1:]
        #s = " "
        #context = s.join(context)
        #curr_path= context.split("|")
        #if len(curr_path)> max:
        #    max = len(curr_path)
    print(m)
