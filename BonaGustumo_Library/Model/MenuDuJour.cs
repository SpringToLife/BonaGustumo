using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BonaGustumo_Library.Model
{
   public class MenuDuJour
    {
        [Key]
        public int Plat_Id { get; set; }

        [Index(IsUnique = true)]
        [Required]
        [Display(Name = "Titre")]
        [MaxLength(100)]
        public string Plat_Titre { get; set; }




       

        public enum Plat_Type { Entrée = 1, Plat = 2, Dessert = 3, Accompagnement = 4, Sauce = 5, Cocktail = 6, Autre = 7 }
        [Display(Name = "Type de plat")]
        public Plat_Type plat_Type{ get; set; }

       

        [Display(Name = "Commentaire")]
        public string Plat_Commentaire { get; set; }
    }
}
