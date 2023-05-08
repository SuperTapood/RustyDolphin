#include "Data.h"

std::vector<Packet*> Data::captured;
int Data::selected = -1;
bool Data::doneCounting = false;
std::array<const char*, 30> Data::quotes = {
	"Less Cheese = More Cheese",
	"'Tis but a scratch!",
    "*sigh* i guess you are my little pugchamp",
    "made with <3",
    "where are my pants?",
    "Spain but the S is silent",
    "now with 5 percent more Bob Ross!",
    "I hardly know 'er!",
    "How you BEAN?",
    "You're breathtaking!",
    "The embodiment of page 2 of google search results",
    "Love is like frying food shirtless, you never know when it's going to hurt",
    "Water is just hydrogen soup",
    "Hey, got any grapes?",
    "'Hello there, old sport!' - an aubergine colored individual",
    "I don't get why circles exist. They're pointless.",
    "I'm afraid for the calendar. Its days are numbered.",
    "If the USA is so great why did they make a USB?",
    "Why are ducks always in a fowl mood?",
    "it is Wednesday my dudes",
    "Approved by official code bros",
    "'If it compiles, it's good; if it boots up, it's perfect.' - Linus Torvalds, Finnish Software Chad",
    "It Just Works.",
    "gotta love it when asynchronization works 60 percent out of 5 percent of the time",
    "The numbers Mason! What do they mean?!?!",
    "funny quote go brrrrr",
    "Built by a part time silly sandwich",
    "'Give someone state and they'll have a bug one day, but teach them how to represent state in two separate locations that have to be kept in sync and they'll have bugs for a lifetime.' - ryg",
    "Panem et Circenses",
    "this quote has been left as an exercise for the reader"
};
long double Data::epochStart;

void Data::addPacket(Packet* p) {
	captured.push_back(p);
}