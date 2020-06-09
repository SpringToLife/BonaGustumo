using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BonaGustumo_Library.DAL
{
    public class BonaGustumoInitializer: CreateDatabaseIfNotExists<BonaGustumoContext>
    {
         protected override void Seed(BonaGustumoContext context)
            {



            //    context.Ingredients.Add(new Ingredient() { Ingredient_Nom = "Lait" });





            //    context.SaveChanges();
            //    base.Seed(context);


            //    var recettes = new List<Recette>
            //{
            //new Recette{Recette_Titre="Navarin"},
            //new Recette{Recette_Titre="tartelette"},
            //new Recette{Recette_Titre="biscuit"},

            //};

            //    recettes.ForEach(rec => context.Recettes.Add(rec));
            //    context.SaveChanges();
            //    base.Seed(context);
            }
        }
    }


