class Crypt:
    cryptograms = []
    xored = []
    messages = []
    charset = ' AĄBCĆDEĘFGHIJKLŁMNOÓPRSTUWYZaąbcćdeęfghijklłmnoóprstuwyz.,?!-"1234567890'

    def __init__(self):
        with open("dane.txt", "r") as f:
            self.cryptograms = f.read()
        self.cryptograms = self.cryptograms.split('\n')
        self.nr_of_cryptograms = len(self.cryptograms)

    def xor(self, first_crypt, second_crypt):
        xored = ''
        for i in range(min(len(first_crypt), len(second_crypt))):
            first_bit = first_crypt[i]
            second_bit = second_crypt[i]
            if first_bit != ' ':
                char = int(first_bit) ^ int(second_bit)
                xored += str(char)
            else:
                xored += " "
        return xored

    def possible_letters(self):
        self.cryptograms.sort(key=lambda x: len(x))
        self.cryptograms.reverse()
        self.xored.sort(key=lambda x: len(x))
        self.xored.reverse()
        self.messages = ['' for _ in range(self.nr_of_cryptograms)]
        self.cryptograms = [c.split(' ') for c in self.cryptograms]
        self.xored = [x.split(' ') for x in self.xored]
        x = 0
        while len(self.xored[0]) - x > 0:
            letters = ['' for _ in range(self.nr_of_cryptograms)]
            for c in self.charset:
                m = self.good_letters(c, x)
                if m != '~':
                    for i in range(self.nr_of_cryptograms):
                        letters[i] += m[i]
            for j in range(self.nr_of_cryptograms):
                if len(letters[j]) > 1:
                    self.messages[j] = self.messages[j] + '||' + letters[j] + '||'
                else:
                    self.messages[j] += letters[j]
            x += 1

    def good_letters(self, letter, index):
        good_letter = ['' for _ in range(self.nr_of_cryptograms)]
        for i in range(self.nr_of_cryptograms):
            if len(self.cryptograms[i]) > index:
                char = chr(int(self.xor('{0:08b}'.format(ord(letter)), self.xored[i][index]), 2))
                if char in self.charset:
                    good_letter[i] = char
                else:
                    return '~'
        return good_letter


a = Crypt()
for i in range(a.nr_of_cryptograms):
    a.xored.append(a.xor(a.cryptograms[0], a.cryptograms[i]))
a.possible_letters()
for i in range(a.nr_of_cryptograms):
    print(a.messages[i])
