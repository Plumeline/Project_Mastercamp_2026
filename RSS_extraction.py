import feedparser
import copy

URL_AVIS = "https://www.cert.ssi.gouv.fr/avis/feed/"
URL_ALERT =  "https://www.cert.ssi.gouv.fr/alerte/feed/"

def get_rss_feed(url, display = False):

    rss_feed = feedparser.parse(url)

    #/avis/alerte/feed/
    #/actualite/feed/

    #display of the rss_feed

    if(display):
        for entry in rss_feed.entries:
            print("Titre :", entry.title)
            print("Description:", entry.description)
            print("Lien :", entry.link)
            print("Date :", entry.published)

    return rss_feed


def get_cleaned_rss_feed(url):

    rss = get_rss_feed(url)

    #the goal is to get only whats useful in the rss feed
    #first we remove the outer dictionary which is of no use whatsoever
    rss = rss['entries']
    #the next layer is the list of data. We will keep this list, but change each data so it contains only the four
    # interesting characteristics
    cleaned_rss =[]
    for alert in rss :
        tempalert = {}

        tempalert['title'] = alert['title']
        tempalert['description'] = alert['description']
        tempalert['link'] = alert['link']
        tempalert['published'] = alert['published']

        cleaned_rss.append(copy.deepcopy(tempalert))

    return cleaned_rss



#rss = get_rss_feed(url, True)

#print(get_cleaned_rss_feed(URL_ALERT))
#print(rss)