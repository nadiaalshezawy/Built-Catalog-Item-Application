#!/usr/bin/env python3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import CategoryItem, Base, Category, User

engine = create_engine('sqlite:///categoriesitem.db')


# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
User1 = User(name="Sulaiman Ibrahim", email="sall1912@hotmail.com")
session.add(User1)
session.commit()

# Items for Bags Category
category1 = Category(user_id=1, name="Bags")

session.add(category1)
session.commit()

categoryItem1 = CategoryItem(
                user_id=1, name="Dior Black", description="""Looking
                for an elegant and chic bag for fun evenings out and special
                occasions? Nothing is more perfect than the Delices Gaufre
                Pearl evening bag from Dior.The top of the bag opens via
                a zipper and the interior is perfect to hold all your
                evening necessities wherever you go. Ideal to
                match with any outfit  you have in mind,
                you do not want to miss out on this beauty!""",
                price="AED 1890", category=category1)

session.add(categoryItem1)
session.commit()


categoryItem2 = CategoryItem(
                user_id=1, name="BOTTEGA Red", description="""
                This gorgeous Bottega Veneta Red Python Knot Clutch
                is the perfect accessory for a fun night out! Featuring
                an exterior of stunning red python leather with black
                leather knot closure on the top, the clutch opens to
                grey interior that can takes your most necessary things
                for an evening out""", price="AED 4500", category=category1)

session.add(categoryItem2)
session.commit()

categoryItem3 = CategoryItem(
                user_id=1, name="Chanel Maroon", description="""
                The  bag from Chanel was designed by Karl Lagerfeld
                both as an interpretation of Coco Chanel's boy charm
                and her love for Boy Capel, one of the first people
                to believe in her. With its soft aged leather maroon
                quilted exterior, this Boy is a little different from
                the usual Chanel design. The medium size makes it
                suitable for work or play and the aged silvertone
                chain-link with leather pad makes it possible to
                wear this as a long strap or looped around as
                shoulder bag. The buckle features the interlocked
                CC closure and opens up to a spacious interior
                that will be suitable to keep all your necessities
                in one place!""", price="AED 8500", category=category1)

session.add(categoryItem3)
session.commit()

categoryItem4 = CategoryItem(
                user_id=1, name="Valentino Green", description="""
                What better way to style up your day or night than
                this chic clutch from Valentino? This gorgeous Rockstud
                flap features smooth leather in Apple Green shade
                adorned around every rim and on the strap handle
                with the famous studs in light gold tone.""",
                price="AED 2490", category=category1)

session.add(categoryItem4)
session.commit()

categoryItem5 = CategoryItem(
                user_id=1, name="Louis Vuitton White", description="""
                The limited edition Onatah GM bag from Louis Vuitton
                is both a chic and practical bag that is ideal to carry
                all day and night. The hobo-style bag gives it a casual
                feel and the soft calfskin exterior in white makes it
                perfect to match with almost any outfit you have in mind.
                The exterior features the iconic Monogram pattern and a
                single leather shoulder strap while the interior
                features floral printed fabric.""",
                price="AED 2690", category=category1)

session.add(categoryItem5)
session.commit()

categoryItem6 = CategoryItem(
                user_id=1, name="Saint Laurent", description="""
                Inspired by the early years of Yves Saint Laurent
                collection, the timeless elegance of the Belle De
                Jour clutch remains the essence of classic French
                style and fine design. The bag features a light blue
                color textured patent leather with the signature YSL
                initials stitched on the flap and a spacious interior
                to keep all your necessities. This clutch is a must
                have addition to your collection and it will be your
                favorite piece for a fun night out!""",
                price="AED 1990", category=category1)

session.add(categoryItem6)
session.commit()

categoryItem7 = CategoryItem(
                user_id=1, name="Gucci Black", description="""
                Gucci Black GG Supreme Canvas Briefcase Bag""",
                price="AED 1990", category=category1)

session.add(categoryItem7)
session.commit()

categoryItem8 = CategoryItem(
                user_id=1, name="Celine", description="""
                Celine bags are one of the most desired bags
                in the world because of its luxurious yet
                subtle elegance. This large beauty features
                stunning Bull calf orange leather exterior,
                rolled leather top handles, braided zipper
                pull and detailed stitching""",
                price="AED 3500", category=category1)

session.add(categoryItem8)
session.commit()

categoryItem9 = CategoryItem(
                user_id=1, name="Miu Miu", description="""
                Designed in a way so you can keep all your
                essentials with you wherever you go, this
                soft Hobo bag from Miu Miu features blue
                crinkled calfskin exterior with one top
                leather handle and polished brass links
                as well as the Miu Miu logo on the front.
                The magnetic closure on top opens to a generously
                spacious beige interior with zipper and patch
                pocket. Beautiful and practical, this Hobo
                Miu Miu bag is the ideal for you!""",
                price="AED 1090", category=category1)

session.add(categoryItem9)
session.commit()


# Items for Shoes
category2 = Category(user_id=1, name="Shoes")

session.add(category1)
session.commit()

categoryItem1 = CategoryItem(
                user_id=1, name="Christian Louboutin Turquoise", description="""
                Since their debut in the fall 2012 collection, the Pigalle
                Spikes by Christian Louboutin have quickly become a favorite
                amongst the A-list stars and we can see why! These pumps
                feature turquoise blue patent leather covered with studs
                of the same color that give it the rocker-chic vibe
                that every woman should own. The contrast of the
                turquoise blue with the red soles make these a
                great choice to go with a casual or chic look
                especially for those summer nights!""",
                price="AED 990", category=category2)

session.add(categoryItem1)
session.commit()

categoryItem2 = CategoryItem(
                user_id=1, name="Valentino Red", description="""
                Nothing is as comfortable and as beautiful as a pair
                of peep toe slingback heels! This pair from Valentino
                feature a fun coral patent leather, small peep toes with
                a big bow on the front of the toe cap and slingback design.
                The 100mm heel is just perfect to wear all day comfortably
                or to add a touch of sexiness for a fun night out!""",
                price="AED 1190", category=category2)

session.add(categoryItem2)
session.commit()

categoryItem3 = CategoryItem(
                user_id=1, name="Dior Yellow", description="""
                Nothing says summer is here like bright and fun
                colors such as this yellow peep toe platforms from
                Gucci! Featuring yellow patent leather, seductive peep
                toe and a 120mm heel, this pair of shoes will surely
                brighten not only your outfit but your mood as well! """,
                price="500", category=category2)

session.add(categoryItem3)
session.commit()

categoryItem4 = CategoryItem(
                user_id=1, name="Versace pink", description="""
                These stunning platforms by Versace are not for
                the weak-hearted for sure! Designed in a multicolor
                leather of pink, white and blue, this pair of sandals
                feature high pink platforms and leather insoles for
                extra comfort when you are partying all night!""",
                price="890", category=category2)

session.add(categoryItem4)
session.commit()

categoryItem5 = CategoryItem(
                user_id=1, name="Gucci classic", description="""
                The Gucci monogram peeptoe pumps are one of the most
                comfortable shoes a lady can own! They are beautifully
                designed with the signature GG logo, leather insoles and
                a seductive peeptoe. Suitable for running your daily errands
                or for a special date night, these heels will go with almost
                any outfit you desire!""", price="1390", category=category2)

session.add(categoryItem5)
session.commit()

categoryItem6 = CategoryItem(
                user_id=1, name="Dolce&Gabbana", description="""
                These stunning wild animal inspired peep toe pumps
                from Dolce and Gabbana feature leopard print in black
                and brown and the top half features white and black
                polka dots. The red insoles contrast beautifully with
                the canvas exterior and the heel gives you the boost
                of confidence you need!""", price="499", category=category2)

session.add(categoryItem6)
session.commit()


# Items for watches
category3 = Category(user_id=1, name="Watches")

session.add(category3)
session.commit()

categoryItem1 = CategoryItem(
                user_id=1, name="Cartier", description="""
                Nothing says luxurious like this stunning
                preloved Cartier tank watch! Designed in full
                18k yellow gold, this beautiful Tank Francis
                shaped watch features diamonds on the sides
                of the dial, roman numbers and white dial with
                the Cartier logo. Get this beautiful and timeless
                Cartier Tank watch today and feel like royalty!""",
                price="AED 75000", category=category3)

session.add(categoryItem1)
session.commit()

categoryItem2 = CategoryItem(
                user_id=1, name="Fendi", description="""
                This stunning My Way watch from Fendi features a
                light pink leather strap, stainless steel dial with
                Swiss-made quartz movement and white dial. The dial
                features the FENDI logo and around it is light pink
                faux fur which gives this feminine watch its unique
                and fun touch!""", price="AED 2590", category=category3)

session.add(categoryItem2)
session.commit()

categoryItem3 = CategoryItem(
                user_id=1, name="chanel watch", description="""
                This gorgeous vintage Premiere watch from Chanel
                dates back to 1987 and it was designed to reflect
                all of Chanel characteristics: elegant, charming and
                feminine. A timeless piece, this watch features
                gold-plated stainless steel with black leather
                chain-link strap, a rectangular bezel with black
                dial and white Chanel logo.""",
                price="AED 6900", category=category3)

session.add(categoryItem3)
session.commit()

categoryItem4 = CategoryItem(
                user_id=1, name="Hermes", description="""
                Lovely and smoothly designed, this stainless-steel
                watch from Hermes features a sapphire crystal with
                a white dial, quartz movements and a case size of 26mm.
                Elegant to wear day and night, this Hermes watch will
                become your favorite in no time!""",
                price="AED 2990", category=category3)

session.add(categoryItem4)
session.commit()

categoryItem5 = CategoryItem(
                user_id=1, name="Gucci watch", description="""
                Gucci Stainless Steel Twirl Watch""",
                price="AED 1800", category=category3)

session.add(categoryItem5)
session.commit()


# Item for Accessories
category4 = Category(user_id=1, name="Accessories")

session.add(category4)
session.commit()

categoryItem1 = CategoryItem(
                user_id=1, name="Chanel earrings", description="""
                Combining her love for pearls and classy looks,
                this pair of Chanel earrings is not only beautiful
                but also reflects the beauty of Coco Chanel. Hat
                shaped clip earrings featuring an interlocked CC
                and a big white pearl in the middle, these are made
                to turn heads! Very unique and rare to find, get
                these today at an amazing price!""",
                price="AED 1940", category=category4)

session.add(categoryItem1)
session.commit()

categoryItem2 = CategoryItem(
                user_id=1, name="LV Bracelet", description="""
                Louis Vuitton Red Patent Keep It Twice Bracelet""",
                price="AED 690", category=category4)

session.add(categoryItem2)
session.commit()

categoryItem3 = CategoryItem(
                user_id=1, name="Chanelbelt", description="""
                This beautiful wide belt from Chanel features black
                lambskin leather and an interlocked CC logo black
                buckle. Wear it with day or night with any outfit
                in mind and add a touch of elegance and style to your look!""",
                price="AED 2690", category=category4)

session.add(categoryItem3)
session.commit()

categoryItem4 = CategoryItem(
                user_id=1, name="Dior bracelet", description="""
                If you love Dior and pearls, then this is the perfect
                accessory for you. It features a matt gold hardware
                chain with many faux pearls in different sizes to
                create a feminine and stylish bracelet. There is also
                one gold tone pearl with the CD logo engraved on it.
                Pair it with your favorite pearl earrings and always
                be in style!""", price="AED 1190", category=category4)

session.add(categoryItem4)
session.commit()

categoryItem5 = CategoryItem(
                user_id=1, name="Fendi Vulpus", description="""
                The Fendi Vulpus Lagopus fur bag charm is the perfect
                accessory to add some fun to your daily bags!""",
                price="AED 1190", category=category4)

session.add(categoryItem5)
session.commit()


print ("added menu items!")
