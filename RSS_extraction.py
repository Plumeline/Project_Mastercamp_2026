import feedparser

def get_rss_feed(display = False):
    url = "https://www.cert.ssi.gouv.fr/feed/"
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