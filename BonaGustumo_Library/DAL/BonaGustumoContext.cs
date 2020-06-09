using System.Data.Entity;
using System.Data.Entity.ModelConfiguration.Conventions;


namespace BonaGustumo_Library.DAL
{
   public class BonaGustumoContext: DbContext
    {
     
            public BonaGustumoContext() : base("DefaultConnection")
            {
                //    //Statégie Initialisation de la BDD
                //Database.SetInitializer<BonaGustumoContext>(new DropCreateDatabaseIfModelChanges<BonaGustumoContext>());
                Database.SetInitializer(new BonaGustumoInitializer());
                //Database.SetInitializer<BonaGustumoContext>(new CreateDatabaseIfNotExists<BonaGustumoContext>());
                //    //Database.SetInitializer<CuisineProContext>(new DropCreateDatabaseAlways<CuisineProContext>());

            }



            //public DbSet<Recette> Recettes { get; set; }
            //public DbSet<Panier> Paniers { get; set; }
            //public DbSet<Ingredient> Ingredients { get; set; }

            protected override void OnModelCreating(DbModelBuilder modelBuilder)
            {
                base.OnModelCreating(modelBuilder);

                modelBuilder.Conventions.Remove<PluralizingTableNameConvention>();
            }

        public System.Data.Entity.DbSet<BonaGustumo_Library.Model.MenuDuJour> MenuDuJours { get; set; }
    }


    }

